"""Tests for DUALR3 motor-mode command gating."""

from __future__ import annotations

import unittest
from typing import Any

from matter_bridge.adapters.ewelink_adapter import EwelinkAdapter
from matter_bridge.adapters.ewelink_protocol import cover_calibrated
from matter_bridge.core.base_adapter import DeviceInfo, DeviceType


class FakeDualR3Adapter(EwelinkAdapter):
    def __init__(self, params: dict[str, Any]) -> None:
        super().__init__({"dual": "key"})
        self.params = params
        self.sent: list[tuple[str, dict[str, Any]]] = []
        self._devices["dual"] = DeviceInfo(
            brand="ewelink", device_id="dual", ip="192.168.1.20", port=8081,
            model="DUALR3", device_type=DeviceType.ON_OFF_PLUG,
            raw_metadata={"type": 126},
        )

    async def _send_command_locked(
        self, device: DeviceInfo, command: str, data: dict[str, Any], apikey: str,
    ) -> dict[str, Any] | None:
        self.sent.append((command, data))
        if command == "info":
            return {"error": 0, "data": {"params": dict(self.params)}}
        return {"error": 0}


class DualR3CoverTests(unittest.IsolatedAsyncioTestCase):
    async def test_position_sends_location_when_calibrated(self) -> None:
        adapter = FakeDualR3Adapter({"workMode": 2, "calibState": 1})
        self.assertTrue(await adapter.set_state("dual", cover={"position": 40}))
        self.assertEqual(adapter.sent[-1], ("location", {"location": 40}))

    async def test_position_refused_until_calibrated(self) -> None:
        for params in ({"workMode": 2, "calibState": 0}, {"workMode": 2}):
            adapter = FakeDualR3Adapter(params)
            self.assertFalse(await adapter.set_state("dual", cover={"position": 40}))
            self.assertEqual([command for command, _ in adapter.sent], ["info"])

    async def test_position_refused_outside_motor_mode(self) -> None:
        adapter = FakeDualR3Adapter({"workMode": 1, "calibState": 1})
        self.assertFalse(await adapter.set_state("dual", cover={"position": 40}))
        self.assertEqual([command for command, _ in adapter.sent], ["info"])

    async def test_rejects_invalid_position_without_network_io(self) -> None:
        adapter = FakeDualR3Adapter({"workMode": 2, "calibState": 1})
        for command in (
            {"position": 101}, {"position": -1}, {"position": 50.0},
            {"position": True}, {"position": 50, "direction": "open"},
        ):
            self.assertFalse(await adapter.set_state("dual", cover=command))
        self.assertEqual(adapter.sent, [])

    async def test_direction_mapping_matches_app(self) -> None:
        adapter = FakeDualR3Adapter({"workMode": 2})
        for direction, value in (("open", 1), ("stop", 0), ("close", 2)):
            self.assertTrue(await adapter.set_state("dual", cover={"direction": direction}))
            self.assertEqual(adapter.sent[-1], ("motorTurn", {"motorTurn": value}))

    def test_app_name_overrides_stored_name(self) -> None:
        adapter = EwelinkAdapter(names={"dual": "Cortina da Sala"})
        device = DeviceInfo(brand="ewelink", device_id="dual", ip="192.168.1.20",
                            port=8081, name="eWeLink_dual")
        adapter.load_device(device)
        self.assertEqual(adapter.get_device("dual").name, "Cortina da Sala")

    def test_calibration_flag_parsing(self) -> None:
        self.assertTrue(cover_calibrated({"calibState": 1}))
        self.assertTrue(cover_calibrated({"calibState": "1"}))
        self.assertFalse(cover_calibrated({"calibState": 0}))
        self.assertIsNone(cover_calibrated({"calibState": True}))
        self.assertIsNone(cover_calibrated({}))
        self.assertIsNone(cover_calibrated(None))


if __name__ == "__main__":
    unittest.main()
