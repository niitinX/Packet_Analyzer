from __future__ import annotations

import argparse
import io
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path
from typing import Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packet_analyzer.dpi_mt import run_mt
from packet_analyzer.dpi_simple import run_simple
from packet_analyzer.pcap_reader import PcapReader
from packet_analyzer.rules import RuleManager


def count_packets(path: str) -> Tuple[int, int]:
    reader = PcapReader(path)
    reader.open()
    total_packets = 0
    total_bytes = 0
    for raw in reader:
        total_packets += 1
        total_bytes += len(raw.data)
    reader.close()
    return total_packets, total_bytes


def benchmark_simple(input_path: str, output_path: str, quiet: bool) -> float:
    rules = RuleManager()
    sink = io.StringIO()
    start = time.perf_counter()
    with redirect_stdout(sink if quiet else sys.stdout):
        run_simple(
            input_path,
            output_path,
            rules,
            throttle_ms=0,
            stats_interval=0.0,
            perf=False,
            quiet=quiet,
        )
    end = time.perf_counter()
    return end - start


def benchmark_mt(input_path: str, output_path: str, lbs: int, fps: int, quiet: bool) -> float:
    rules = RuleManager()
    sink = io.StringIO()
    start = time.perf_counter()
    with redirect_stdout(sink if quiet else sys.stdout):
        run_mt(
            input_path,
            output_path,
            rules,
            lbs,
            fps,
            throttle_ms=0,
            stats_interval=0.0,
            perf=False,
            quiet=quiet,
        )
    end = time.perf_counter()
    return end - start


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DPI benchmark runner")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("--mode", choices=["simple", "mt"], default="simple")
    parser.add_argument("--lbs", type=int, default=2)
    parser.add_argument("--fps", type=int, default=2)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    packets, total_bytes = count_packets(args.input)

    times = []
    for idx in range(args.repeat):
        out_path = f"bench_output_{args.mode}_{idx}.pcap"
        if args.mode == "simple":
            elapsed = benchmark_simple(args.input, out_path, args.quiet)
        else:
            elapsed = benchmark_mt(args.input, out_path, args.lbs, args.fps, args.quiet)
        times.append(elapsed)

    avg = sum(times) / len(times)
    pps = packets / avg if avg > 0 else 0.0
    mbps = (total_bytes / (1024 * 1024)) / avg if avg > 0 else 0.0

    print(f"Mode: {args.mode}")
    print(f"Packets: {packets}")
    print(f"Bytes: {total_bytes}")
    print(f"Runs: {len(times)}")
    print(f"Avg seconds: {avg:.4f}")
    print(f"Throughput: {pps:.2f} packets/sec")
    print(f"Throughput: {mbps:.2f} MiB/sec")


if __name__ == "__main__":
    main()
