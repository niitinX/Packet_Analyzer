from __future__ import annotations

import argparse
import ipaddress
import threading
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional

from .pcap_reader import PcapReader, PcapWriter, RawPacket
from .packet_parser import ParsedPacket, parse_packet, PROTO_UDP
from .rules import RuleManager
from .sni_extractor import extract_http_host, extract_tls_sni
from .thread_safe_queue import ThreadSafeQueue
from .dpi_types import AppType, Flow, FiveTuple, sni_to_app_type


@dataclass
class PacketItem:
    raw: RawPacket
    parsed: ParsedPacket


class FastPath:
    def __init__(
        self,
        rules: RuleManager,
        output_queue: ThreadSafeQueue[RawPacket],
    ) -> None:
        self.rules = rules
        self.output_queue = output_queue
        self.queue: ThreadSafeQueue[PacketItem] = ThreadSafeQueue()
        self.flows: Dict[FiveTuple, Flow] = {}
        self.stats = Counter()
        self.forwarded = 0
        self.dropped = 0
        self.processed = 0
        self.detected_domains: Dict[str, AppType] = {}
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self) -> None:
        self._thread.join()

    def _classify(self, pkt: ParsedPacket, flow: Flow) -> Flow:
        if flow.sni:
            return flow

        if pkt.dst_port == 443 and pkt.payload:
            sni = extract_tls_sni(pkt.payload)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                self.detected_domains[sni] = flow.app_type
                return flow

        if pkt.dst_port == 80 and pkt.payload:
            host = extract_http_host(pkt.payload)
            if host:
                flow.sni = host
                flow.app_type = AppType.HTTP
                self.detected_domains[host] = flow.app_type

        if pkt.protocol == PROTO_UDP and pkt.dst_port == 53:
            flow.app_type = AppType.DNS

        return flow

    def _run(self) -> None:
        while True:
            item = self.queue.pop()
            if item is None:
                break

            self.processed += 1
            flow = self.flows.setdefault(item.parsed.tuple, Flow())
            flow = self._classify(item.parsed, flow)
            if self.rules.is_blocked(item.parsed.src_ip, flow.app_type, flow.sni):
                flow.blocked = True

            if flow.blocked:
                self.dropped += 1
                continue

            self.forwarded += 1
            self.stats[flow.app_type] += 1
            self.output_queue.push(item.raw)


class LoadBalancer:
    def __init__(self, fps: List[FastPath]) -> None:
        self.fps = fps
        self.queue: ThreadSafeQueue[PacketItem] = ThreadSafeQueue()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.dispatched = 0

    def start(self) -> None:
        self._thread.start()

    def join(self) -> None:
        self._thread.join()

    def _run(self) -> None:
        num_fps = len(self.fps)
        while True:
            item = self.queue.pop()
            if item is None:
                break
            idx = hash(item.parsed.tuple) % num_fps
            self.fps[idx].queue.push(item)
            self.dispatched += 1


class OutputWriter:
    def __init__(self, output_path: str) -> None:
        self.output_path = output_path
        self.queue: ThreadSafeQueue[RawPacket] = ThreadSafeQueue()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._writer: Optional[PcapWriter] = None

    def start(self) -> None:
        self._thread.start()

    def join(self) -> None:
        self._thread.join()

    def _run(self) -> None:
        self._writer = PcapWriter(self.output_path)
        self._writer.open()
        while True:
            item = self.queue.pop()
            if item is None:
                break
            self._writer.write_packet(item.header, item.data)
        self._writer.close()


BOX_WIDTH = 70


def _box_line(text: str) -> str:
    return f"║{text:<{BOX_WIDTH}}║"


def _box_top() -> str:
    return "╔" + "═" * BOX_WIDTH + "╗"


def _box_mid() -> str:
    return "╠" + "═" * BOX_WIDTH + "╣"


def _box_bottom() -> str:
    return "╚" + "═" * BOX_WIDTH + "╝"


def _format_app_name(app: AppType) -> str:
    overrides = {
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.UNKNOWN: "Unknown",
    }
    return overrides.get(app, app.value.replace("_", " ").title())


def _render_bar(pct: float, width: int = 20) -> str:
    filled = int(round((pct / 100.0) * width)) if pct > 0 else 0
    return "#" * filled


def _print_rules(rules: RuleManager) -> None:
    for app in sorted(rules.blocked_apps, key=lambda a: a.value):
        print(f"[Rules] Blocked app: {_format_app_name(app)}")
    for ip_int in sorted(rules.blocked_ips):
        ip_str = str(ipaddress.IPv4Address(ip_int))
        print(f"[Rules] Blocked IP: {ip_str}")
    for domain in sorted(rules.blocked_domains):
        print(f"[Rules] Blocked domain: {domain}")


def _print_header(lbs: int, fps: int) -> None:
    print(_box_top())
    print(_box_line("              DPI ENGINE v2.0 (Multi-threaded)"))
    print(_box_mid())
    total_fps = lbs * fps
    config = f" Load Balancers:  {lbs:<2}    FPs per LB:  {fps:<2}    Total FPs:  {total_fps:<3}"
    print(_box_line(config))
    print(_box_bottom())


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DPI engine (multi-threaded)")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("--lbs", type=int, default=2)
    parser.add_argument("--fps", type=int, default=2)
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    return parser.parse_args()


def _build_rules(args: argparse.Namespace) -> RuleManager:
    rules = RuleManager()
    for app_name in args.block_app:
        try:
            rules.add_block_app(AppType(app_name.lower()))
        except ValueError:
            raise SystemExit(f"Unknown app type: {app_name}")
    for ip_str in args.block_ip:
        ipaddress.IPv4Address(ip_str)
        rules.add_block_ip(ip_str)
    for domain in args.block_domain:
        rules.add_block_domain(domain)
    return rules


def run_mt(input_path: str, output_path: str, rules: RuleManager, lbs: int, fps: int) -> None:
    reader = PcapReader(input_path)
    reader.open()

    _print_header(lbs, fps)
    _print_rules(rules)
    print("\n[Reader] Processing packets...")

    output = OutputWriter(output_path)
    output.start()

    fast_paths = [FastPath(rules, output.queue) for _ in range(fps)]
    for fp in fast_paths:
        fp.start()

    load_balancers = [LoadBalancer(fast_paths) for _ in range(lbs)]
    for lb in load_balancers:
        lb.start()

    total = 0
    total_bytes = 0
    tcp_packets = 0
    udp_packets = 0
    for raw in reader:
        parsed = parse_packet(raw.data)
        if not parsed:
            continue

        total_bytes += len(raw.data)
        if parsed.protocol == 6:
            tcp_packets += 1
        elif parsed.protocol == PROTO_UDP:
            udp_packets += 1

        item = PacketItem(raw=raw, parsed=parsed)
        lb_idx = hash(parsed.tuple) % lbs
        load_balancers[lb_idx].queue.push(item)
        total += 1

    reader.close()
    print(f"[Reader] Done reading {total} packets")

    for lb in load_balancers:
        lb.queue.close()
    for lb in load_balancers:
        lb.join()

    for fp in fast_paths:
        fp.queue.close()
    for fp in fast_paths:
        fp.join()

    output.queue.close()
    output.join()

    forwarded = sum(fp.forwarded for fp in fast_paths)
    dropped = sum(fp.dropped for fp in fast_paths)

    app_stats = Counter()
    for fp in fast_paths:
        app_stats.update(fp.stats)

    detected: Dict[str, AppType] = {}
    for fp in fast_paths:
        detected.update(fp.detected_domains)

    print("")
    print(_box_top())
    print(_box_line("                      PROCESSING REPORT"))
    print(_box_mid())
    print(_box_line(f" Total Packets: {total:>16}"))
    print(_box_line(f" Total Bytes: {total_bytes:>18}"))
    print(_box_line(f" TCP Packets: {tcp_packets:>17}"))
    print(_box_line(f" UDP Packets: {udp_packets:>17}"))
    print(_box_mid())
    print(_box_line(f" Forwarded: {forwarded:>20}"))
    print(_box_line(f" Dropped: {dropped:>22}"))
    print(_box_mid())
    print(_box_line(" THREAD STATISTICS"))
    for idx, lb in enumerate(load_balancers):
        print(_box_line(f"   LB{idx} dispatched: {lb.dispatched:>13}"))
    for idx, fp in enumerate(fast_paths):
        print(_box_line(f"   FP{idx} processed: {fp.processed:>14}"))
    print(_box_mid())
    print(_box_line("                   APPLICATION BREAKDOWN"))
    print(_box_mid())
    for app, count in app_stats.most_common():
        pct = (count / total * 100.0) if total else 0.0
        bar = _render_bar(pct)
        label = _format_app_name(app)
        blocked = " (BLOCKED)" if app in rules.blocked_apps else ""
        line = f" {label:<18} {count:>3} {pct:>5.1f}% {bar:<20}{blocked}"
        print(_box_line(line[:BOX_WIDTH]))
    print(_box_bottom())

    if detected:
        print("\n[Detected Domains/SNIs]")
        for domain, app in sorted(detected.items()):
            print(f"  - {domain} -> {_format_app_name(app)}")


def main() -> None:
    args = _parse_args()
    rules = _build_rules(args)
    run_mt(args.input, args.output, rules, args.lbs, args.fps)


if __name__ == "__main__":
    main()
