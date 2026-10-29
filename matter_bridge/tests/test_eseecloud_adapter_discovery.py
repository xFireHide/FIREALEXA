"""EseeCloud adapter inventory behaviour for LAN NVR discovery.

Exercises datagram handling without opening real sockets. Synthetic responses
are not hardware evidence.
"""

import unittest

from matter_bridge.adapters.eseecloud_adapter import EseeCloudAdapter
from matter_bridge.core.base_adapter import DeviceType


_NVR_RESPONSE = (
    b'{"Esee-ID":"EE-ABC","Device-Model":"NVR-4","Channel-Cnt":4,'
    b'"Capabilities":{"Http-Port":8080}}'
)


class EseeCloudDiscoveryAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_datagram_creates_unverified_inventory(self):
        adapter = EseeCloudAdapter()
        await adapter._handle_discovery_datagram(_NVR_RESPONSE, "192.168.1.20")

        devices = await adapter.discover(timeout=0.0)
        inventory = [d for d in devices if d.device_id.startswith("esee-nvr-")]
        self.assertEqual(len(inventory), 1)
        device = inventory[0]
        self.assertEqual(device.device_id, "esee-nvr-EE-ABC")
        self.assertEqual(device.ip, "192.168.1.20")
        self.assertEqual(device.device_type, DeviceType.CAMERA)
        self.assertFalse(device.raw_metadata["verified"])
        self.assertEqual(device.raw_metadata["discovery_protocol"], "eseecloud_lan_nvr")

        state = await adapter.get_state(device.device_id)
        self.assertTrue(state.online)
        self.assertFalse(state.raw["streamable"])

    async def test_inventory_camera_is_not_streamable(self):
        adapter = EseeCloudAdapter()
        await adapter.start()
        try:
            await adapter._handle_discovery_datagram(_NVR_RESPONSE, "192.168.1.20")
            # No stream target was configured, so authentication must refuse it.
            device = adapter._inventory["esee-nvr-EE-ABC"]
            self.assertFalse(await adapter.authenticate(device))
            with self.assertRaises(KeyError):
                async with adapter.stream("esee-nvr-EE-ABC"):
                    pass
        finally:
            await adapter.stop()

    async def test_repeated_datagram_updates_without_duplicating(self):
        adapter = EseeCloudAdapter()
        await adapter._handle_discovery_datagram(_NVR_RESPONSE, "192.168.1.20")
        await adapter._handle_discovery_datagram(_NVR_RESPONSE, "192.168.1.33")
        devices = await adapter.discover(timeout=0.0)
        inventory = [d for d in devices if d.device_id.startswith("esee-nvr-")]
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0].ip, "192.168.1.33")

    async def test_load_device_round_trips_inventory_entry(self):
        source = EseeCloudAdapter()
        await source._handle_discovery_datagram(_NVR_RESPONSE, "192.168.1.20")
        stored = source._inventory["esee-nvr-EE-ABC"]

        # A fresh adapter (restart) must accept the persisted inventory entry.
        reloaded = EseeCloudAdapter()
        reloaded.load_device(stored)
        self.assertIn("esee-nvr-EE-ABC", reloaded._inventory)

    async def test_configured_stream_is_not_shadowed_by_discovery(self):
        adapter = EseeCloudAdapter(
            {"esee-nvr-EE-ABC": {"ip": "192.168.1.50", "channel": 12}}
        )
        # The configured ID collides with the derived inventory ID; the
        # configured stream target must win and stay streamable.
        await adapter._handle_discovery_datagram(_NVR_RESPONSE, "192.168.1.20")
        self.assertNotIn("esee-nvr-EE-ABC", adapter._inventory)
        self.assertIn("esee-nvr-EE-ABC", adapter._targets)


if __name__ == "__main__":
    unittest.main()
