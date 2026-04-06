from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional, Tuple

PCAP_MAGIC_BE = 0xA1B2C3D4
PCAP_MAGIC_LE = 0xD4C3B2A1


@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes


class PcapReader:
    def __init__(self, path: str) -> None:
        self.path = path
        self._fh: Optional[BinaryIO] = None
        self.endian = "<"
        self.global_header: Optional[PcapGlobalHeader] = None

    def open(self) -> None:
        self._fh = open(self.path, "rb")
        raw = self._fh.read(24)
        if len(raw) != 24:
            raise ValueError("Invalid PCAP: missing global header")

        magic = struct.unpack("<I", raw[:4])[0]
        if magic == PCAP_MAGIC_LE:
            self.endian = "<"
        elif magic == PCAP_MAGIC_BE:
            self.endian = ">"
        else:
            raise ValueError("Invalid PCAP: bad magic number")

        fields = struct.unpack(self.endian + "IHHIIII", raw)
        self.global_header = PcapGlobalHeader(*fields)

    def read_next_packet(self) -> Optional[RawPacket]:
        if not self._fh:
            raise RuntimeError("PCAP file not open")

        header_raw = self._fh.read(16)
        if not header_raw:
            return None
        if len(header_raw) != 16:
            raise ValueError("Invalid PCAP: truncated packet header")

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            self.endian + "IIII", header_raw
        )
        data = self._fh.read(incl_len)
        if len(data) != incl_len:
            raise ValueError("Invalid PCAP: truncated packet data")

        header = PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len)
        return RawPacket(header=header, data=data)

    def __iter__(self) -> Iterator[RawPacket]:
        while True:
            pkt = self.read_next_packet()
            if pkt is None:
                break
            yield pkt

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


class PcapWriter:
    def __init__(self, path: str, *, snaplen: int = 65535, network: int = 1) -> None:
        self.path = path
        self.snaplen = snaplen
        self.network = network
        self._fh: Optional[BinaryIO] = None
        self.endian = "<"

    def open(self) -> None:
        self._fh = open(self.path, "wb")
        header = struct.pack(
            self.endian + "IHHIIII",
            PCAP_MAGIC_LE,
            2,
            4,
            0,
            0,
            self.snaplen,
            self.network,
        )
        self._fh.write(header)

    def write_packet(self, header: PcapPacketHeader, data: bytes) -> None:
        if not self._fh:
            raise RuntimeError("PCAP writer not open")
        packed = struct.pack(
            self.endian + "IIII",
            header.ts_sec,
            header.ts_usec,
            len(data),
            header.orig_len,
        )
        self._fh.write(packed)
        self._fh.write(data)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
