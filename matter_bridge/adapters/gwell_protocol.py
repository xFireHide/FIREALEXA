"""Gwell/Yoosee LAN search datagrams (UDP 8899).

Layout from Yoosee 6.46.1 (``dl.i`` ``LocalNetSearchProcessor`` and
``el.a`` ``LocalNetGDevInfo``). Java's default big-endian ``ByteBuffer`` order
applies to every integer. The app broadcasts the request to port 8899 and
receives replies on its own bound port 8899.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

GWELL_SEARCH_PORT = 8899
SEARCH_CMD = 1
REPLY_CMD = 2
REQUEST_LENGTH = 1024  # The app sends its whole 1024-byte buffer.
PARSED_LENGTH = 200  # The app parses only the first 200 bytes of a reply.
_HEADER_LENGTH = 28


@dataclass(frozen=True)
class GwellSearchReply:
    device_id: int
    error_code: int
    flags: int
    device_type: int
    flag: int
    sub_type: int | None
    custom_id: int | None
    mac: str | None
    local_p2p_port: int | None


def build_search_request() -> bytes:
    """Return the app's search datagram: cmd=1, leftLength=28, zero padding."""
    header = struct.pack(">8i", SEARCH_CMD, 0, _HEADER_LENGTH, 0, 0, 0, 0, 0)
    return header.ljust(REQUEST_LENGTH, b"\x00")


def _bit(value: int, bit: int) -> bool:
    return (value >> bit) & 1 == 1


def _mac(data: bytes) -> str | None:
    # Bytes 60-61 and 64-67 are each stored reversed.
    raw = data[60:62][::-1] + data[64:68][::-1]
    if raw == b"\x00" * 6 or raw[0] & 1:
        return None
    return ":".join(f"{byte:02x}" for byte in raw)


def parse_search_reply(data: bytes) -> GwellSearchReply | None:
    """Parse a search reply, or return None for requests and malformed packets."""
    if len(data) < _HEADER_LENGTH:
        return None
    # Mirror the app, which reads from a zero-filled buffer.
    data = data[:PARSED_LENGTH].ljust(PARSED_LENGTH, b"\x00")
    cmd, error_code, _left, flags, device_id, device_type, flag = struct.unpack_from(
        ">7i", data, 0
    )
    if cmd != REPLY_CMD or device_id <= 0:
        return None

    def int_at(offset: int) -> int:
        return struct.unpack_from(">i", data, offset)[0]

    sub_type = custom_id = local_p2p_port = None
    mac = None
    if _bit(flags, 6):
        if _bit(flags, 0):
            custom_id = int_at(68)
        if _bit(flags, 4):
            sub_type = int_at(80)
        if _bit(flags, 8):
            mac = _mac(data)
    else:
        sub_type = int_at(80)
        if flags & 1:
            custom_id = int_at(68)
        port = int_at(84) & 0xFFFF
        local_p2p_port = port or None
        mac = _mac(data)
    return GwellSearchReply(
        device_id=device_id,
        error_code=error_code,
        flags=flags,
        device_type=device_type,
        flag=flag,
        sub_type=sub_type,
        custom_id=custom_id,
        mac=mac,
        local_p2p_port=local_p2p_port,
    )
