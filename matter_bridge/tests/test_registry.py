"""Regression tests for device validation and credential-free persistence."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from matter_bridge.core.base_adapter import DeviceInfo, DeviceType
from matter_bridge.core.registry import DeviceRegistry
from matter_bridge.discovery.network import is_lan_unicast_address


class LanAddressTests(unittest.TestCase):
    def test_accepts_private_and_link_local_unicast(self) -> None:
        for address in ("192.168.1.10", "10.20.0.4", "169.254.1.9", "fd00::1234"):
            with self.subTest(address=address):
                self.assertTrue(is_lan_unicast_address(address))

    def test_rejects_non_lan_and_non_unicast_addresses(self) -> None:
        for address in ("8.8.8.8", "127.0.0.1", "0.0.0.0", "224.0.0.1", "not-an-ip"):
            with self.subTest(address=address):
                self.assertFalse(is_lan_unicast_address(address))


class DeviceRegistryTests(unittest.TestCase):
    def test_migrates_legacy_credentials_out_of_persisted_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "devices.json"
            path.write_text(json.dumps([{
                "brand": "broadlink",
                "device_id": "aa:bb:cc:dd:ee:ff",
                "ip": "192.168.1.20",
                "port": 80,
                "model": "RM4 Mini",
                "device_type": "IR_REMOTE",
                "raw_metadata": {"devtype": 0x520C},
                "auth_token": "746f6b656e",
                "session_key": bytes(range(16)).hex(),
            }]), encoding="utf-8")

            registry = DeviceRegistry(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            loaded = registry.get("broadlink", "aa:bb:cc:dd:ee:ff")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.device_type, DeviceType.IR_REMOTE)
            self.assertEqual(loaded.raw_metadata, {"devtype": 0x520C})
            self.assertEqual(loaded.auth_token, b"")
            self.assertEqual(loaded.session_key, b"")
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("auth_token", persisted[0])
            self.assertNotIn("session_key", persisted[0])

    def test_refresh_keeps_credentials_and_descriptive_fields(self) -> None:
        registry = DeviceRegistry()
        first = DeviceInfo(
            brand="ewelink", device_id="dev-1", ip="192.168.1.2", port=8081,
            model="Basic", name="Hall", device_type=DeviceType.ON_OFF_PLUG,
            auth_token=b"secret",
        )
        registry.register(first)
        registry.register(DeviceInfo(
            brand="ewelink", device_id="dev-1", ip="192.168.1.3", port=8081,
            device_type=DeviceType.UNKNOWN,
        ))

        refreshed = registry.get("ewelink", "dev-1")
        self.assertIsNotNone(refreshed)
        assert refreshed is not None
        self.assertEqual(refreshed.ip, "192.168.1.3")
        self.assertEqual(refreshed.model, "Basic")
        self.assertEqual(refreshed.name, "Hall")
        self.assertEqual(refreshed.device_type, DeviceType.ON_OFF_PLUG)
        self.assertEqual(refreshed.auth_token, b"secret")

    def test_rejects_invalid_addresses_ports_and_credential_types(self) -> None:
        registry = DeviceRegistry()
        base = dict(brand="xiaomi", device_id="123", ip="192.168.1.2", port=54321)
        invalid = (
            DeviceInfo(**{**base, "ip": "8.8.8.8"}),
            DeviceInfo(**{**base, "port": True}),
            DeviceInfo(**{**base, "port": 65536}),
            DeviceInfo(**{**base, "auth_token": "not-bytes"}),
        )
        for device in invalid:
            with self.subTest(device=device):
                with self.assertRaises(ValueError):
                    registry.register(device)

    def test_loader_skips_malformed_entries_and_rewrites_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "devices.json"
            path.write_text(json.dumps([
                {"brand": "ewelink", "device_id": "ok", "ip": "192.168.1.4",
                 "port": 8081, "device_type": "ON_OFF_PLUG"},
                {"brand": "ewelink", "device_id": "bad", "ip": "8.8.8.8",
                 "port": 8081},
            ]), encoding="utf-8")

            registry = DeviceRegistry(path)

            self.assertEqual([device.device_id for device in registry.all_devices()], ["ok"])
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(len(persisted), 1)
            self.assertEqual(persisted[0]["device_id"], "ok")


if __name__ == "__main__":
    unittest.main()
