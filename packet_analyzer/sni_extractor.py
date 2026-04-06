from __future__ import annotations

from typing import Optional


def _read_u16_be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def extract_tls_sni(payload: bytes) -> Optional[str]:
    if len(payload) < 6:
        return None

    # TLS record header
    if payload[0] != 0x16:
        return None
    if payload[5] != 0x01:
        return None

    offset = 43
    if offset >= len(payload):
        return None

    # Session ID
    if offset + 1 > len(payload):
        return None
    session_len = payload[offset]
    offset += 1 + session_len
    if offset + 2 > len(payload):
        return None

    # Cipher suites
    cipher_len = _read_u16_be(payload, offset)
    offset += 2 + cipher_len
    if offset + 1 > len(payload):
        return None

    # Compression methods
    comp_len = payload[offset]
    offset += 1 + comp_len
    if offset + 2 > len(payload):
        return None

    # Extensions
    ext_len = _read_u16_be(payload, offset)
    offset += 2
    ext_end = offset + ext_len
    if ext_end > len(payload):
        return None

    while offset + 4 <= ext_end:
        ext_type = _read_u16_be(payload, offset)
        ext_data_len = _read_u16_be(payload, offset + 2)
        offset += 4
        if offset + ext_data_len > ext_end:
            return None

        if ext_type == 0x0000:
            if offset + 5 > ext_end:
                return None
            sni_len = _read_u16_be(payload, offset + 3)
            sni_start = offset + 5
            sni_end = sni_start + sni_len
            if sni_end > ext_end:
                return None
            return payload[sni_start:sni_end].decode("utf-8", errors="ignore")

        offset += ext_data_len

    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    try:
        text = payload.decode("latin1", errors="ignore")
    except UnicodeDecodeError:
        return None

    if not (text.startswith("GET ") or text.startswith("POST ") or text.startswith("HEAD ")):
        return None

    for line in text.split("\r\n"):
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()

    return None
