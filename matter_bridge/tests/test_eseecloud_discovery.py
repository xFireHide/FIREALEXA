"""Tests for EseeCloud LAN discovery parsing and inventory records."""

from __future__ import annotations

import json
import unittest

from matter_bridge.adapters.eseecloud_adapter import (
    LAN_DISCOVERY_PROTOCOL,
    EseeCloudAdapter,
)
from matter_bridge.adapters.eseecloud_discovery import (
    REQUEST_ID,
    build_discovery_request,
    parse_discovery_reply,
)
from matter_bridge.core.base_adapter import DeviceInfo, DeviceType

SECRET_KEYS = ("UID", "devKey", "ulinkToken")


def camera_reply(**overrides: object) -> bytes:
    message = {
        "fromApp": False,
        "requestID": REQUEST_ID,
        "deviceID": "1234567890",
        "UID": "SECRET-UID-123",
        "devKey": "secret-dev-key",
        "version": "1.2",
        "devinfo": {
            "deviceType": "IPC", "maxChannel": 1, "enableChannel": 1,
            "monopoly": False, "ulinkToken": "secret-token",
        },
    }
    message.update(overrides)
    return json.dumps(message).encode()


class EseeCloudDiscoveryProtocolTests(unittest.TestCase):
    def test_request_matches_app_json(self) -> None:
        self.assertEqual(json.loads(build_discovery_request()), {
            "fromApp": True, "requestID": 134489421, "tokenID": "1473433878",
            "command": "discovery", "version": "1.0",
        })

    def test_parses_reply_without_credentials(self) -> None:
        reply = parse_discovery_reply(camera_reply())
        assert reply is not None
        self.assertEqual(reply.device_id, "1234567890")
        self.assertEqual(reply.device_type, "IPC")
        self.assertEqual(reply.max_channel, 1)
        self.assertEqual(reply.version, "1.2")
        for secret in ("SECRET-UID-123", "secret-dev-key", "secret-token"):
            self.assertNotIn(secret, repr(reply))

    def test_ignores_requests_other_ids_and_malformed_data(self) -> None:
        for data in (
            build_discovery_request(),
            camera_reply(requestID=1),
            camera_reply(fromApp="false"),
            camera_reply(deviceID="../etc"),
            camera_reply(deviceID=12345),
            b"\xff\xfe", b"[]", b"{", b"x" * 9000,
        ):
            self.assertIsNone(parse_discovery_reply(data), data[:40])

    def test_invalid_optional_fields_become_none(self) -> None:
        reply = parse_discovery_reply(camera_reply(
            version=1.2, devinfo={"deviceType": "\n", "maxChannel": True},
        ))
        assert reply is not None
        self.assertIsNone(reply.version)
        self.assertIsNone(reply.device_type)
        self.assertIsNone(reply.max_channel)


class EseeCloudDiscoveryAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovered_camera_is_inventory_only(self) -> None:
        adapter = EseeCloudAdapter()
        reply = parse_discovery_reply(camera_reply())
        assert reply is not None
        adapter._record_reply("192.168.1.50", reply)
        device = adapter.get_device("esee-1234567890")
        assert device is not None
        self.assertEqual(device.ip, "192.168.1.50")
        self.assertEqual(device.raw_metadata["discovery_protocol"], LAN_DISCOVERY_PROTOCOL)
        self.assertFalse(adapter.has_stream(device.device_id))
        state = await adapter.get_state(device.device_id)
        self.assertTrue(state.online)
        self.assertFalse(state.raw["stream_available"])
        stored = repr(device)
        for secret in ("SECRET-UID-123", "secret-dev-key", "secret-token", *SECRET_KEYS):
            self.assertNotIn(secret, stored)

    async def test_reply_annotates_configured_stream_at_same_ip(self) -> None:
        adapter = EseeCloudAdapter({"porch": {"ip": "192.168.1.50", "channel": 12}})
        reply = parse_discovery_reply(camera_reply())
        assert reply is not None
        adapter._record_reply("192.168.1.50", reply)
        self.assertEqual(list(adapter._devices), ["porch"])
        porch = adapter.get_device("porch")
        assert porch is not None
        self.assertEqual(porch.raw_metadata["eseecloud_device_id"], "1234567890")
        self.assertEqual(porch.raw_metadata["discovery_protocol"],
                         "eseecloud_http_stream_config")

    def test_load_device_accepts_discovered_records_only(self) -> None:
        adapter = EseeCloudAdapter()
        adapter.load_device(DeviceInfo(
            brand="eseecloud", device_id="esee-1", ip="192.168.1.9", port=80,
            device_type=DeviceType.CAMERA,
            raw_metadata={"discovery_protocol": LAN_DISCOVERY_PROTOCOL},
        ))
        self.assertIsNotNone(adapter.get_device("esee-1"))
        with self.assertRaises(ValueError):
            adapter.load_device(DeviceInfo(
                brand="eseecloud", device_id="other", ip="192.168.1.9", port=80,
                device_type=DeviceType.CAMERA, raw_metadata={},
            ))


if __name__ == "__main__":
    unittest.main()
