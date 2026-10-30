"""Tests for EseeCloud LAN discovery parsing and inventory records."""

from __future__ import annotations

import json
import unittest

from matter_bridge.adapters.eseecloud_adapter import (
    LAN_DISCOVERY_PROTOCOL,
    NVR_DISCOVERY_PROTOCOL,
    EseeCloudAdapter,
)
from matter_bridge.adapters.eseecloud_discovery import (
    REQUEST_ID,
    build_discovery_request,
    build_nvr_request,
    parse_discovery_reply,
    parse_nvr_reply,
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


NVR_REPLY = (
    b'garbage {"Esee-ID":"EE12345","Device-ID":"dev-1","Device-Model":"NVR-8",'
    b'"Device-Type":"NVR","Channel-Cnt":8,"Software-Version":"1.2.3",'
    b'"Nonce":"secret-nonce","Ver":"1.1","Capabilities":{"Http-Port":8080}}'
)


class EseeCloudNvrProtocolTests(unittest.TestCase):
    def test_request_matches_app_bytes(self) -> None:
        self.assertEqual(
            build_nvr_request(2),
            b"SEARCH * HDS/1.1\r\nCSeq:2\r\n"
            b"Client-ID:CeCOlDpmTuzViBQDgbrPgFkfnyyzNabc\r\n"
            b"Accept-Type:text/HDP\r\nContent-Length:13\r\n"
            b'X-Search-Type:NVR\r\n{"Ver":"1.1"}',
        )
        with self.assertRaises(ValueError):
            build_nvr_request(True)  # type: ignore[arg-type]

    def test_parses_reply_without_nonce(self) -> None:
        reply = parse_nvr_reply(NVR_REPLY)
        assert reply is not None
        self.assertEqual(reply.esee_id, "EE12345")
        self.assertEqual(reply.device_model, "NVR-8")
        self.assertEqual(reply.channel_count, 8)
        self.assertEqual(reply.http_port, 8080)
        self.assertNotIn("secret-nonce", repr(reply))

    def test_rejects_missing_id_and_malformed_data(self) -> None:
        self.assertIsNone(parse_nvr_reply(b'{"Device-ID":"dev-1"}'))
        self.assertIsNone(parse_nvr_reply(b'{"Esee-ID":""}'))
        self.assertIsNone(parse_nvr_reply(b"no json"))
        self.assertIsNone(parse_nvr_reply(b"[1]"))
        self.assertIsNone(parse_nvr_reply(b'{"Esee-ID":"x"}' + b" " * 9000))
        reply = parse_nvr_reply(b'{"Esee-ID":"E1","Channel-Cnt":"8","Capabilities":42}')
        assert reply is not None
        self.assertIsNone(reply.channel_count)
        self.assertIsNone(reply.http_port)


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

    async def test_nvr_reply_is_inventory_only(self) -> None:
        adapter = EseeCloudAdapter()
        reply = parse_nvr_reply(NVR_REPLY)
        assert reply is not None
        adapter._record_reply("192.168.1.60", reply)
        device = adapter.get_device("esee-EE12345")
        assert device is not None
        self.assertEqual(device.port, 8080)
        self.assertEqual(device.model, "NVR-8")
        self.assertEqual(device.raw_metadata["discovery_protocol"], NVR_DISCOVERY_PROTOCOL)
        self.assertFalse(adapter.has_stream(device.device_id))
        self.assertFalse(await adapter.authenticate(device))
        self.assertNotIn("secret-nonce", repr(device))
        reloaded = EseeCloudAdapter()
        reloaded.load_device(device)
        self.assertIsNotNone(reloaded.get_device("esee-EE12345"))

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
