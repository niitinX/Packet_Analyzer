from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Dict


@dataclass
class StatsSnapshot:
    total_packets: int
    total_bytes: int
    tcp_packets: int
    udp_packets: int
    forwarded: int
    dropped: int


class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_packets = 0
        self._total_bytes = 0
        self._tcp_packets = 0
        self._udp_packets = 0
        self._forwarded = 0
        self._dropped = 0

    def record_packet(self, size: int, *, is_tcp: bool, is_udp: bool) -> None:
        with self._lock:
            self._total_packets += 1
            self._total_bytes += size
            if is_tcp:
                self._tcp_packets += 1
            if is_udp:
                self._udp_packets += 1

    def record_forwarded(self) -> None:
        with self._lock:
            self._forwarded += 1

    def record_dropped(self) -> None:
        with self._lock:
            self._dropped += 1

    def snapshot(self) -> StatsSnapshot:
        with self._lock:
            return StatsSnapshot(
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                tcp_packets=self._tcp_packets,
                udp_packets=self._udp_packets,
                forwarded=self._forwarded,
                dropped=self._dropped,
            )


class LiveStatsPrinter:
    def __init__(self, stats: Stats, interval_sec: float) -> None:
        self._stats = stats
        self._interval = interval_sec
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        if self._interval <= 0:
            return
        self._thread.start()

    def stop(self) -> None:
        if self._interval <= 0:
            return
        self._stop.set()
        self._thread.join()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            snap = self._stats.snapshot()
            print(
                "[Stats] total={t} fwd={f} drop={d} bytes={b}".format(
                    t=snap.total_packets,
                    f=snap.forwarded,
                    d=snap.dropped,
                    b=snap.total_bytes,
                )
            )
