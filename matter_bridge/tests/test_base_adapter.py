"""Tests for shared adapter state cache and lifecycle behavior."""

from __future__ import annotations

import asyncio
import unittest
from typing import Any

from matter_bridge.core.base_adapter import BaseAdapter, DeviceInfo, DeviceState


class DummyAdapter(BaseAdapter):
    BRAND = "test"

    async def discover(self, timeout: float | None = None) -> list[DeviceInfo]:
        return []

    async def authenticate(self, device: DeviceInfo) -> bool:
        return True

    async def get_state(self, device_id: str) -> DeviceState:
        return DeviceState()

    async def set_state(self, device_id: str, **kwargs: Any) -> bool:
        return True


class BaseAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_offline_sample_keeps_last_known_values_and_merges_raw(self) -> None:
        adapter = DummyAdapter()
        await adapter.publish_state("sensor-1", DeviceState(
            online=True, temperature=21.5, humidity=40.0,
            raw={"source": "lan", "revision": 1},
        ))

        await adapter.publish_state("sensor-1", DeviceState(
            online=False, temperature=None, raw={"error": "timeout", "revision": 2},
        ))

        state = adapter.get_cached_state("sensor-1")
        self.assertIsNotNone(state)
        assert state is not None
        self.assertFalse(state.online)
        self.assertEqual(state.temperature, 21.5)
        self.assertEqual(state.humidity, 40.0)
        self.assertEqual(state.raw, {
            "source": "lan", "revision": 2, "error": "timeout",
        })

    async def test_bad_subscriber_does_not_prevent_other_subscribers(self) -> None:
        adapter = DummyAdapter()
        received: list[DeviceState] = []

        async def broken(_device_id: str, _state: DeviceState) -> None:
            raise RuntimeError("subscriber failed")

        async def healthy(_device_id: str, state: DeviceState) -> None:
            received.append(state)

        await adapter.subscribe("device-1", broken)
        await adapter.subscribe("device-1", healthy)
        expected = DeviceState(online=True, on=True)

        await adapter.publish_state("device-1", expected)

        self.assertEqual(received, [expected])
        self.assertIs(adapter.get_cached_state("device-1"), expected)

    async def test_stop_cancels_and_joins_background_tasks(self) -> None:
        adapter = DummyAdapter()
        await adapter.start()
        task = asyncio.create_task(asyncio.Event().wait())
        adapter._tasks.append(task)

        await adapter.stop()

        self.assertFalse(adapter.running)
        self.assertTrue(task.cancelled())
        self.assertEqual(adapter._tasks, [])


if __name__ == "__main__":
    unittest.main()
