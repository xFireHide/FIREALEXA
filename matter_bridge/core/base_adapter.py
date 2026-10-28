"""
Abstract base classes for brand-specific device adapters.

Each adapter handles: discovery → auth → command → state polling
for a specific brand's LAN protocol.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, fields
from enum import Enum, auto
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """Standardized device capability types mapped to Matter clusters."""
    UNKNOWN = auto()
    ON_OFF_LIGHT = auto()
    DIMMABLE_LIGHT = auto()
    COLOR_LIGHT = auto()
    ON_OFF_PLUG = auto()
    TEMPERATURE_SENSOR = auto()
    HUMIDITY_SENSOR = auto()
    ENVIRONMENT_SENSOR = auto()
    CONTACT_SENSOR = auto()
    MOTION_SENSOR = auto()
    THERMOSTAT = auto()
    WINDOW_COVERING = auto()
    IR_REMOTE = auto()
    RF_REMOTE = auto()
    CAMERA = auto()  # ONVIF motion events; video streams are not a Matter endpoint


@dataclass
class DeviceInfo:
    """Unified device descriptor after discovery."""
    brand: str
    device_id: str
    ip: str
    port: int
    mac: str = ""
    model: str = ""
    firmware: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    name: str = ""
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    auth_token: bytes = b""
    session_key: bytes = b""


@dataclass
class DeviceState:
    """Snapshot of a device's current state."""
    online: bool = False
    on: bool | None = None
    brightness: int | None = None  # 0-100
    color_temp: int | None = None  # mireds
    hue: int | None = None  # 0-360
    saturation: int | None = None  # 0-100
    temperature: float | None = None  # celsius
    humidity: float | None = None  # 0-100%
    cover_position: int | None = None  # device-specific percentage, when reported
    cover_motion: str | None = None  # opening, closing, or stopped when reported
    contact_open: bool | None = None
    motion_detected: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict)


# Type alias for state change callbacks
StateCallback = Callable[[str, DeviceState], Coroutine[Any, Any, None]]


class BaseAdapter(ABC):
    """
    Abstract base for brand-specific LAN adapters.

    Lifecycle:
        1. discover() → yields DeviceInfo for each found device
        2. authenticate(device) → establishes session
        3. get_state(device) → returns current DeviceState
        4. set_state(device, **kwargs) → sends command
        5. subscribe(device, callback) → registers push/poll listener
    """

    BRAND: str = "unknown"
    DISCOVERY_TIMEOUT: float = 5.0
    COMMAND_TIMEOUT: float = 3.0
    RECONNECT_DELAY: float = 2.0
    MAX_RECONNECT_ATTEMPTS: int = 5

    def __init__(self) -> None:
        self._devices: dict[str, DeviceInfo] = {}
        self._states: dict[str, DeviceState] = {}
        self._callbacks: dict[str, list[StateCallback]] = {}
        self._running = False
        self._tasks: list[asyncio.Task] = []

    @abstractmethod
    async def discover(self, timeout: float | None = None) -> list[DeviceInfo]:
        """Discover devices on the local network."""
        ...

    @abstractmethod
    async def authenticate(self, device: DeviceInfo) -> bool:
        """Perform LAN authentication/pairing handshake."""
        ...

    @abstractmethod
    async def get_state(self, device_id: str) -> DeviceState:
        """Query current device state."""
        ...

    @abstractmethod
    async def set_state(self, device_id: str, **kwargs: Any) -> bool:
        """
        Send a command to the device.

        Common kwargs:
            on: bool - power state
            brightness: int - 0-100
            color_temp: int - mireds
            hue: int, saturation: int - color
        """
        ...

    async def subscribe(self, device_id: str, callback: StateCallback) -> None:
        """Register a callback for state changes."""
        self._callbacks.setdefault(device_id, []).append(callback)

    async def _notify_state_change(self, device_id: str, state: DeviceState) -> None:
        """Fire all registered callbacks for a device."""
        previous = self._states.get(device_id)
        if not state.online and previous is not None:
            # Keep last-known measurements and raw protocol fields for UI/API
            # consumers while marking the snapshot stale through online=False.
            # Adapters use None to mean "not observed", so a later offline
            # response must not erase a previously observed value.
            merged: dict[str, Any] = {}
            for state_field in fields(DeviceState):
                name = state_field.name
                if name == "online":
                    merged[name] = False
                elif name == "raw":
                    merged[name] = {**previous.raw, **state.raw}
                else:
                    current = getattr(state, name)
                    merged[name] = (
                        getattr(previous, name) if current is None else current
                    )
            state = DeviceState(**merged)
        self._states[device_id] = state
        for cb in tuple(self._callbacks.get(device_id, [])):
            try:
                await cb(device_id, state)
            except Exception:
                logger.exception("State callback error for %s", device_id)

    async def publish_state(self, device_id: str, state: DeviceState) -> None:
        """Update the cached state and notify subscribers."""
        await self._notify_state_change(device_id, state)

    async def start(self) -> None:
        """Start the adapter's background tasks (polling, listeners)."""
        if self._running:
            return
        self._running = True
        logger.info("[%s] Adapter started", self.BRAND)

    async def stop(self) -> None:
        """Gracefully stop all background tasks."""
        if not self._running and not self._tasks:
            return
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("[%s] Adapter stopped", self.BRAND)

    def get_device(self, device_id: str) -> DeviceInfo | None:
        return self._devices.get(device_id)

    def get_cached_state(self, device_id: str) -> DeviceState | None:
        return self._states.get(device_id)

    @property
    def devices(self) -> dict[str, DeviceInfo]:
        return dict(self._devices)

    @property
    def running(self) -> bool:
        """Whether this adapter's lifecycle has been started."""
        return self._running

    async def _reconnect_loop(
        self,
        device_id: str,
        connect_fn: Callable[[], Coroutine[Any, Any, bool]],
    ) -> None:
        """Generic reconnection loop with exponential backoff."""
        attempts = 0
        delay = self.RECONNECT_DELAY
        while self._running and attempts < self.MAX_RECONNECT_ATTEMPTS:
            try:
                if await connect_fn():
                    logger.info("[%s] Reconnected to %s", self.BRAND, device_id)
                    return
            except Exception:
                logger.warning(
                    "[%s] Reconnect attempt %d/%d for %s failed",
                    self.BRAND, attempts + 1, self.MAX_RECONNECT_ATTEMPTS, device_id,
                )
            attempts += 1
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)
        logger.error("[%s] Failed to reconnect to %s", self.BRAND, device_id)
