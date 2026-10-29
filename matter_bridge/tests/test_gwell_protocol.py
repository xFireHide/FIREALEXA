"""Tests for the Yoosee/Gwell LAN search datagrams."""

from __future__ import annotations

import struct
import unittest

from matter_bridge.adapters.gwell_protocol import (
    REQUEST_LENGTH,
    build_search_request,
    parse_search_reply,
)


def reply(flags: int, **fields: int) -> bytearray:
    data = bytearray(200)
    struct.pack_into(">7i", data, 0, 2, 0, 28, flags, 7654321, 7, 0)
    for offset, value in fields.items():
        struct.pack_into(">i", data, int(offset.removeprefix("at")), value)
    return data


class GwellProtocolTests(unittest.TestCase):
    def test_request_matches_app_layout(self) -> None:
        request = build_search_request()
        self.assertEqual(len(request), REQUEST_LENGTH)
        self.assertEqual(struct.unpack_from(">8i", request), (1, 0, 28, 0, 0, 0, 0, 0))
        self.assertEqual(request[32:], b"\x00" * (REQUEST_LENGTH - 32))

    def test_own_request_and_short_packets_are_ignored(self) -> None:
        self.assertIsNone(parse_search_reply(build_search_request()))
        self.assertIsNone(parse_search_reply(b"\x00\x00\x00\x02" + b"\x00" * 10))
        self.assertIsNone(parse_search_reply(bytes(reply(0, at16=0))))

    def test_legacy_reply_layout(self) -> None:
        data = reply(1, at68=11, at80=3, at84=(0x0A00 << 16) | 51880)
        data[60:62] = bytes([0x22, 0x10])  # stored reversed
        data[64:68] = bytes([0x66, 0x55, 0x44, 0x33])
        parsed = parse_search_reply(bytes(data))
        assert parsed is not None
        self.assertEqual(parsed.device_id, 7654321)
        self.assertEqual(parsed.device_type, 7)
        self.assertEqual(parsed.sub_type, 3)
        self.assertEqual(parsed.custom_id, 11)
        self.assertEqual(parsed.local_p2p_port, 51880)
        self.assertEqual(parsed.mac, "10:22:33:44:55:66")

    def test_flagged_reply_reads_only_advertised_fields(self) -> None:
        flags = (1 << 6) | (1 << 4)
        parsed = parse_search_reply(bytes(reply(flags, at68=11, at80=5)))
        assert parsed is not None
        self.assertEqual(parsed.sub_type, 5)
        self.assertIsNone(parsed.custom_id)
        self.assertIsNone(parsed.mac)
        self.assertIsNone(parsed.local_p2p_port)

    def test_short_reply_is_zero_filled_like_app(self) -> None:
        parsed = parse_search_reply(bytes(reply(0))[:28])
        assert parsed is not None
        self.assertEqual(parsed.sub_type, 0)
        self.assertIsNone(parsed.mac)


if __name__ == "__main__":
    unittest.main()
