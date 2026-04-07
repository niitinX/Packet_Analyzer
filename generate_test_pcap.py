from __future__ import annotations

import struct
from dataclasses import dataclass
import random
from typing import List, Optional

from packet_analyzer.pcap_reader import PcapPacketHeader, PcapWriter


def _mac(addr: str) -> bytes:
    return bytes(int(part, 16) for part in addr.split(":"))


def _ipv4(addr: str) -> int:
    parts = [int(p) for p in addr.split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _ipv4_bytes(addr: str) -> bytes:
    return struct.pack("!I", _ipv4(addr))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet(src_mac: str, dst_mac: str, eth_type: int, payload: bytes) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", eth_type) + payload


def _ipv4_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    ver_ihl = 0x45
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        0,
        total_len,
        0,
        0,
        64,
        proto,
        0,
        _ipv4_bytes(src_ip),
        _ipv4_bytes(dst_ip),
    )
    csum = _checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:]


def _tcp_header(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    data_offset = 5
    offset_flags = (data_offset << 12) | flags
    window = 8192
    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        window,
        0,
        0,
    )
    pseudo = struct.pack(
        "!4s4sBBH",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        0,
        6,
        len(header) + len(payload),
    )
    csum = _checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:]


def _udp_header(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = struct.pack(
        "!4s4sBBH",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        0,
        17,
        length,
    )
    csum = _checksum(pseudo + header + payload)
    return struct.pack("!HHHH", src_port, dst_port, length, csum)


def _tls_client_hello_sni(host: str) -> bytes:
    host_bytes = host.encode("utf-8")
    sni_list = struct.pack("!HBH", len(host_bytes) + 3, 0, len(host_bytes)) + host_bytes
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01"
        + b"\x00"
        + struct.pack("!H", len(sni_ext))
        + sni_ext
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def _http_get_host(host: str) -> bytes:
    return (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dpi-test\r\n\r\n".encode(
            "ascii"
        )
    )


def _build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    seq: int = 1,
    ack: int = 0,
    flags: int = 0x18,
) -> bytes:
    ip_header = _ipv4_header(src_ip, dst_ip, 6, 20 + len(payload))
    tcp_header = _tcp_header(src_port, dst_port, seq, ack, flags, payload)
    ip_header = _ipv4_header(src_ip, dst_ip, 6, len(tcp_header) + len(payload))
    return ip_header + tcp_header + payload


def _build_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    udp_header = _udp_header(src_port, dst_port, payload)
    ip_header = _ipv4_header(src_ip, dst_ip, 17, len(udp_header) + len(payload))
    return ip_header + udp_header + payload


@dataclass
class PacketSpec:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes
    proto: str


def _add_tls_flow(
    samples: List[PacketSpec],
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    host: str,
    extra_packets: int,
) -> None:
    samples.append(
        PacketSpec(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=443,
            payload=_tls_client_hello_sni(host),
            proto="tcp",
        )
    )
    for idx in range(extra_packets):
        payload = b"\x17\x03\x03\x00\x10" + bytes([idx]) * 16
        samples.append(
            PacketSpec(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=443,
                payload=payload,
                proto="tcp",
            )
        )


def _add_http_flow(
    samples: List[PacketSpec],
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    host: str,
    extra_packets: int,
) -> None:
    samples.append(
        PacketSpec(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=80,
            payload=_http_get_host(host),
            proto="tcp",
        )
    )
    for _ in range(extra_packets):
        samples.append(
            PacketSpec(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=80,
                payload=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                proto="tcp",
            )
        )


def _add_dns_packets(
    samples: List[PacketSpec],
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    count: int,
) -> None:
    payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for _ in range(count):
        samples.append(
            PacketSpec(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=53,
                payload=payload,
                proto="udp",
            )
        )


def build_sample_packets(
    *,
    randomize: bool = False,
    seed: Optional[int] = None,
    size_factor: int = 1,
) -> List[PacketSpec]:
    samples: List[PacketSpec] = []

    rng = random.Random(seed) if randomize else None

    tls_hosts = [
        "www.youtube.com",
        "www.facebook.com",
        "github.com",
        "www.google.com",
        "www.tiktok.com",
        "video.twimg.com",
        "www.instagram.com",
        "www.reddit.com",
        "www.netflix.com",
        "www.spotify.com",
        "www.linkedin.com",
        "www.apple.com",
        "www.microsoft.com",
        "www.amazon.com",
        "www.paypal.com",
        "www.cloudflare.com",
        "www.stackoverflow.com",
        "www.nytimes.com",
        "www.bbc.com",
        "www.notion.so",
        "www.dropbox.com",
        "www.slack.com",
        "www.zoom.us",
        "discord.com",
        "www.twitch.tv",
        "www.roblox.com",
        "www.pinterest.com",
        "www.quora.com",
        "www.medium.com",
        "www.wikipedia.org",
        "www.pornhub.org",
        "www.xnxx.com",
        "www.redtube.com",
        "www.brazzers.com",
        
    ]
    http_hosts = [
        "example.com",
        "news.ycombinator.com",
        "docs.python.org",
        "www.wikipedia.org",
        "httpbin.org",
        "developer.mozilla.org",
        "api.github.com",
        "www.gnu.org",
        "www.kernel.org",
        "www.rfc-editor.org",
        "www.iana.org",
        "www.apache.org",
        "www.nginx.com",
        "www.postgresql.org",
        "www.mysql.com",
        "www.ruby-lang.org",
        "www.rust-lang.org",
        "www.go.dev",
        "www.docker.com",
        "www.kubernetes.io",
    ]

    if randomize and rng:
        rng.shuffle(tls_hosts)
        rng.shuffle(http_hosts)

    def pick_extra(min_v: int, max_v: int) -> int:
        base = rng.randint(min_v, max_v) if rng else max_v
        return max(1, base * size_factor)

    tls_count = (4 if not randomize else rng.randint(3, 5)) * size_factor
    for idx in range(tls_count):
        host = tls_hosts[idx % len(tls_hosts)]
        _add_tls_flow(
            samples,
            src_ip=f"192.168.1.{100 + idx}",
            dst_ip="142.250.185.206",
            src_port=50000 + idx * 5,
            host=host,
            extra_packets=pick_extra(2, 6),
        )

    http_count = (1 if not randomize else rng.randint(1, 2)) * size_factor
    for idx in range(http_count):
        host = http_hosts[idx % len(http_hosts)]
        _add_http_flow(
            samples,
            src_ip=f"192.168.1.{120 + idx}",
            dst_ip="93.184.216.34",
            src_port=51000 + idx * 3,
            host=host,
            extra_packets=pick_extra(1, 4),
        )

    _add_dns_packets(
        samples,
        src_ip="192.168.1.200",
        dst_ip="8.8.8.8",
        src_port=53000,
        count=pick_extra(2, 6),
    )

    return samples


def write_test_pcap(
    path: str,
    *,
    verbose: bool = True,
    randomize: bool = False,
    seed: Optional[int] = None,
    size_factor: int = 1,
) -> int:
    writer = PcapWriter(path)
    writer.open()

    ts = 1712420000
    samples = build_sample_packets(randomize=randomize, seed=seed, size_factor=size_factor)
    for spec in samples:
        if spec.proto == "tcp":
            ip_payload = _build_tcp_packet(
                spec.src_ip,
                spec.dst_ip,
                spec.src_port,
                spec.dst_port,
                spec.payload,
            )
        else:
            ip_payload = _build_udp_packet(
                spec.src_ip,
                spec.dst_ip,
                spec.src_port,
                spec.dst_port,
                spec.payload,
            )

        frame = _ethernet(
            src_mac="00:11:22:33:44:55",
            dst_mac="aa:bb:cc:dd:ee:ff",
            eth_type=0x0800,
            payload=ip_payload,
        )
        header = PcapPacketHeader(ts, 0, len(frame), len(frame))
        writer.write_packet(header, frame)
        ts += 1

    writer.close()
    if verbose:
        print(f"Wrote {path} ({len(samples)} packets)")
    return len(samples)


def main() -> None:
    write_test_pcap("test_dpi.pcap")


if __name__ == "__main__":
    main()
