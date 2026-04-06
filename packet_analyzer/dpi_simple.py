from __future__ import annotations

import argparse
import ipaddress
import time
from collections import Counter
from typing import Dict

from .pcap_reader import PcapReader, PcapWriter
from .packet_parser import ParsedPacket, parse_packet, PROTO_UDP
from .live_stats import LiveStatsPrinter, Stats
from .rules import RuleManager
from .sni_extractor import extract_http_host, extract_tls_sni
from .dpi_types import AppType, Flow, FiveTuple, sni_to_app_type


def _app_from_packet(pkt: ParsedPacket, flow: Flow) -> Flow:
    if flow.sni:
        return flow

    if pkt.dst_port == 443 and pkt.payload:
        sni = extract_tls_sni(pkt.payload)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
            return flow

    if pkt.dst_port == 80 and pkt.payload:
        host = extract_http_host(pkt.payload)
        if host:
            flow.sni = host
            flow.app_type = AppType.HTTP

    if pkt.protocol == PROTO_UDP and pkt.dst_port == 53:
        flow.app_type = AppType.DNS

    return flow


def run_simple(
    input_path: str,
    output_path: str,
    rules: RuleManager,
    *,
    throttle_ms: int,
    stats_interval: float,
    perf: bool,
) -> None:
    start_time = time.perf_counter()
    reader = PcapReader(input_path)
    reader.open()

    writer = PcapWriter(output_path)
    writer.open()

    flows: Dict[FiveTuple, Flow] = {}
    app_stats = Counter()
    forwarded = 0
    dropped = 0
    stats = Stats()
    detected: Dict[str, AppType] = {}

    stats_printer = LiveStatsPrinter(stats, stats_interval)
    stats_printer.start()

    print("DPI ENGINE v2.0 (Single-threaded)")
    for app in sorted(rules.blocked_apps, key=lambda a: a.value):
        print(f"[Rules] Blocked app: {_format_app_name(app)}")
    for ip_int in sorted(rules.blocked_ips):
        ip_str = str(ipaddress.IPv4Address(ip_int))
        print(f"[Rules] Blocked IP: {ip_str}")
    for domain in sorted(rules.blocked_domains):
        print(f"[Rules] Blocked domain: {domain}")
    print("\n[Reader] Processing packets...")

    for raw in reader:
        parsed = parse_packet(raw.data)
        if not parsed:
            continue

        stats.record_packet(
            len(raw.data),
            is_tcp=parsed.protocol == 6,
            is_udp=parsed.protocol == PROTO_UDP,
        )

        flow = flows.setdefault(parsed.tuple, Flow())
        flow = _app_from_packet(parsed, flow)
        if rules.is_blocked(parsed.src_ip, flow.app_type, flow.sni):
            flow.blocked = True

        if flow.sni:
            detected[flow.sni] = flow.app_type

        if flow.blocked:
            dropped += 1
            stats.record_dropped()
            continue

        if throttle_ms > 0:
            time.sleep(throttle_ms / 1000.0)

        forwarded += 1
        stats.record_forwarded()
        writer.write_packet(raw.header, raw.data)
        app_stats[flow.app_type] += 1

    reader.close()
    writer.close()
    stats_printer.stop()

    snapshot = stats.snapshot()

    print(f"[Reader] Done reading {snapshot.total_packets} packets\n")
    print(_box_top())
    print(_box_line("                      PROCESSING REPORT"))
    print(_box_mid())
    print(_box_line(f" Total Packets: {snapshot.total_packets:>16}"))
    print(_box_line(f" Total Bytes: {snapshot.total_bytes:>18}"))
    print(_box_line(f" TCP Packets: {snapshot.tcp_packets:>17}"))
    print(_box_line(f" UDP Packets: {snapshot.udp_packets:>17}"))
    print(_box_mid())
    print(_box_line(f" Forwarded: {snapshot.forwarded:>20}"))
    print(_box_line(f" Dropped: {snapshot.dropped:>22}"))
    print(_box_mid())
    print(_box_line("                   APPLICATION BREAKDOWN"))
    print(_box_mid())
    for app, count in app_stats.most_common():
        pct = (count / snapshot.total_packets * 100.0) if snapshot.total_packets else 0.0
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

    if perf:
        elapsed = time.perf_counter() - start_time
        pps = snapshot.total_packets / elapsed if elapsed > 0 else 0.0
        mib_per_sec = (snapshot.total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0
        print("\n[Performance]")
        print(f"  Elapsed: {elapsed:.4f} sec")
        print(f"  Throughput: {pps:.2f} packets/sec")
        print(f"  Throughput: {mib_per_sec:.2f} MiB/sec")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DPI engine (single-threaded)")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    parser.add_argument("--rules-in", help="Load rules from JSON file")
    parser.add_argument("--rules-out", help="Save rules to JSON file after run")
    parser.add_argument("--throttle-ms", type=int, default=0)
    parser.add_argument("--stats-interval", type=float, default=0.0)
    parser.add_argument("--perf", action="store_true")
    return parser.parse_args()


BOX_WIDTH = 62


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


def _build_rules(args: argparse.Namespace) -> RuleManager:
    rules = RuleManager.load(args.rules_in) if args.rules_in else RuleManager()
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


def main() -> None:
    args = _parse_args()
    rules = _build_rules(args)
    run_simple(
        args.input,
        args.output,
        rules,
        throttle_ms=args.throttle_ms,
        stats_interval=args.stats_interval,
        perf=args.perf,
    )
    if args.rules_out:
        rules.save(args.rules_out)


if __name__ == "__main__":
    main()
