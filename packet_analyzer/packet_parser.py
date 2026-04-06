from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .dpi_types import FiveTuple

ETH_TYPE_IPV4 = 0x0800
PROTO_TCP = 6
PROTO_UDP = 17


@dataclass
class ParsedPacket:
    src_mac: str
    dst_mac: str
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int
    payload: bytes

    @property
    def tuple(self) -> FiveTuple:
        return FiveTuple(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
        )


def _mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("!H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("!I", data, offset)[0]


def parse_packet(frame: bytes) -> Optional[ParsedPacket]:
    if len(frame) < 14:
        return None

    dst_mac = _mac_to_str(frame[0:6])
    src_mac = _mac_to_str(frame[6:12])
    eth_type = _read_u16(frame, 12)
    if eth_type != ETH_TYPE_IPV4:
        return None

    if len(frame) < 34:
        return None

    ip_offset = 14
    ver_ihl = frame[ip_offset]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return None

    if len(frame) < ip_offset + ihl:
        return None

    protocol = frame[ip_offset + 9]
    src_ip = _read_u32(frame, ip_offset + 12)
    dst_ip = _read_u32(frame, ip_offset + 16)

    l4_offset = ip_offset + ihl
    if protocol == PROTO_TCP:
        if len(frame) < l4_offset + 20:
            return None
        src_port = _read_u16(frame, l4_offset)
        dst_port = _read_u16(frame, l4_offset + 2)
        data_offset = (frame[l4_offset + 12] >> 4) * 4
        if data_offset < 20:
            return None
        payload_offset = l4_offset + data_offset
    elif protocol == PROTO_UDP:
        if len(frame) < l4_offset + 8:
            return None
        src_port = _read_u16(frame, l4_offset)
        dst_port = _read_u16(frame, l4_offset + 2)
        payload_offset = l4_offset + 8
    else:
        return None

    if payload_offset > len(frame):
        return None

    payload = frame[payload_offset:]
    return ParsedPacket(
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        payload=payload,
    )
