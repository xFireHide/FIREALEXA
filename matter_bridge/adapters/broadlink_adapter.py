"""
Broadlink LAN adapter.

Discovery: UDP broadcast to port 80
Auth: AES-128-CBC handshake with default key → session key
Control: AES-encrypted binary commands over UDP
Devices: RM4, RM Mini, SP2/SP3, A1 sensors
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import socket
import struct
from typing import Any

from matter_bridge.core.base_adapter import (
    BaseAdapter,
    DeviceInfo,
    DeviceState,
    DeviceType,
)
from matter_bridge.crypto.broadlink_crypto import (
    DEFAULT_IV,
    DEFAULT_KEY,
    build_header,
    decrypt,
    encrypt,
    finalize_packet,
    parse_auth_response,
    validate_response,
)
from matter_bridge.discovery.network import (
    get_ipv4_broadcast_interfaces,
    get_local_ipv4,
    is_lan_unicast_address,
)

logger = logging.getLogger(__name__)
POLL_INTERVAL = 10.0

# Known device types (devtype → (name, DeviceType))
_DEVTYPE_MAP: dict[int, tuple[str, DeviceType]] = {
    # RM Mini
    0x2737: ("RM Mini", DeviceType.IR_REMOTE),
    0x27C2: ("RM Mini 3", DeviceType.IR_REMOTE),
    # RM Pro / RM4
    0x2712: ("RM Pro", DeviceType.IR_REMOTE),
    0x273D: ("RM Pro Phicomm", DeviceType.IR_REMOTE),
    0x272A: ("RM Pro+", DeviceType.IR_REMOTE),
    0x2783: ("RM2 Home Plus", DeviceType.IR_REMOTE),
    0x277C: ("RM2 Home Plus GDT", DeviceType.IR_REMOTE),
    0x2787: ("RM2 Pro Plus2", DeviceType.IR_REMOTE),
    0x278B: ("RM2 Pro Plus BL", DeviceType.IR_REMOTE),
    0x278F: ("RM Mini Shate", DeviceType.IR_REMOTE),
    0x6026: ("RM4 Pro", DeviceType.IR_REMOTE),
    0x61A2: ("RM4 Pro", DeviceType.IR_REMOTE),
    0x6184: ("RM4C Pro", DeviceType.IR_REMOTE),
    0x5209: ("RM4 TV Mate", DeviceType.IR_REMOTE),
    0x520B: ("RM4 Pro", DeviceType.IR_REMOTE),
    0x520C: ("RM4 Mini", DeviceType.IR_REMOTE),
    0x520D: ("RM4C Mini", DeviceType.IR_REMOTE),
    0x5211: ("RM4C Mate", DeviceType.IR_REMOTE),
    0x5212: ("RM4 TV Mate", DeviceType.IR_REMOTE),
    0x5213: ("RM4 Pro", DeviceType.IR_REMOTE),
    0x5216: ("RM4 Mini", DeviceType.IR_REMOTE),
    0x5218: ("RM4C Pro", DeviceType.IR_REMOTE),
    0x521C: ("RM4 Mini", DeviceType.IR_REMOTE),
    0x6070: ("RM4C Mini", DeviceType.IR_REMOTE),
    0x610E: ("RM4 Mini", DeviceType.IR_REMOTE),
    0x610F: ("RM4C Mini", DeviceType.IR_REMOTE),
    0x62BC: ("RM4 Mini", DeviceType.IR_REMOTE),
    0x62BE: ("RM4C Mini", DeviceType.IR_REMOTE),
    0x51DA: ("RM4 Mini", DeviceType.IR_REMOTE),
    0x6364: ("RM4S", DeviceType.IR_REMOTE),
    0x648D: ("RM4 Mini", DeviceType.IR_REMOTE),
    0x649B: ("RM4 Pro", DeviceType.IR_REMOTE),
    0x6539: ("RM4C Mini", DeviceType.IR_REMOTE),
    0x653A: ("RM4 Mini", DeviceType.IR_REMOTE),
    0x653C: ("RM4 Pro", DeviceType.IR_REMOTE),
    0x5F36: ("RM Mini 3", DeviceType.IR_REMOTE),
    0x6507: ("RM Mini 3", DeviceType.IR_REMOTE),
    0x6508: ("RM Mini 3", DeviceType.IR_REMOTE),
    # SP2/SP3 smart plugs
    0x2711: ("SP2", DeviceType.ON_OFF_PLUG),
    0x2716: ("NEO PRO", DeviceType.ON_OFF_PLUG),
    0x2717: ("NEO", DeviceType.ON_OFF_PLUG),
    0x2719: ("SP2 (compatible)", DeviceType.ON_OFF_PLUG),
    0x7919: ("SP2 (compatible)", DeviceType.ON_OFF_PLUG),
    0x271A: ("SP2 (compatible)", DeviceType.ON_OFF_PLUG),
    0x791A: ("SP2 (compatible)", DeviceType.ON_OFF_PLUG),
    0x271D: ("Ego", DeviceType.ON_OFF_PLUG),
    0x2720: ("SP Mini", DeviceType.ON_OFF_PLUG),
    0x2728: ("SP2 compatible (URANT)", DeviceType.ON_OFF_PLUG),
    0x2733: ("SP3", DeviceType.ON_OFF_PLUG),
    0x2736: ("SP Mini Plus", DeviceType.ON_OFF_PLUG),
    0x273E: ("SP Mini", DeviceType.ON_OFF_PLUG),
    0x7530: ("SP2 OEM", DeviceType.ON_OFF_PLUG),
    0x7539: ("SP2-IL", DeviceType.ON_OFF_PLUG),
    0x753E: ("SP Mini 3", DeviceType.ON_OFF_PLUG),
    0x7540: ("MP2", DeviceType.ON_OFF_PLUG),
    0x7544: ("SP2-CL", DeviceType.ON_OFF_PLUG),
    0x7546: ("SP2-UK/BR/IN", DeviceType.ON_OFF_PLUG),
    0x7547: ("SC1", DeviceType.ON_OFF_PLUG),
    0x7549: ("SP Mini 3", DeviceType.ON_OFF_PLUG),
    0x7918: ("SP2 OEM", DeviceType.ON_OFF_PLUG),
    0x7D00: ("SP3-EU", DeviceType.ON_OFF_PLUG),
    0x7D0D: ("SP Mini 3", DeviceType.ON_OFF_PLUG),
    0x947A: ("SP3S", DeviceType.ON_OFF_PLUG),
    0x9479: ("SP3S", DeviceType.ON_OFF_PLUG),
    # A1 environment sensor
    0x2714: ("A1", DeviceType.TEMPERATURE_SENSOR),
}

# python-broadlink's rmminib/rm4mini command classes use a length-prefixed
# command envelope; older RM models use a four-byte command prefix.
_NEW_COMMAND_PROTOCOL_DEVTYPES = {
    0x5F36, 0x6507, 0x6508,
    0x51DA, 0x5209, 0x520B, 0x520C, 0x520D, 0x5211, 0x5212, 0x5213,
    0x5216, 0x5218, 0x521C, 0x6070, 0x610E, 0x610F, 0x6184, 0x62BC,
    0x62BE, 0x6364, 0x648D, 0x649B, 0x6539, 0x653A, 0x653C, 0x6026,
    0x61A2,
}
_RM4_SENSOR_DEVTYPES = _NEW_COMMAND_PROTOCOL_DEVTYPES - {0x5F36, 0x6507, 0x6508}
_SP3_NIGHTLIGHT_DEVTYPES = {0x2733, 0x7D00}


class BroadlinkDevice:
    """Internal state for a single Broadlink device connection."""

    def __init__(self, info: DeviceInfo) -> None:
        self.info = info
        self.key = DEFAULT_KEY
        self.iv = DEFAULT_IV
        self.device_id_int: int = 0
        self.count: int = 0
        self.authenticated: bool = False
        self.online: bool = False
        self.session_error: bool = False
        self.devtype: int = 0
        self.transport: asyncio.DatagramTransport | None = None
        self.lock = asyncio.Lock()
        self.auth_lock = asyncio.Lock()
        self.ir_lock = asyncio.Lock()


class BroadlinkAdapter(BaseAdapter):
    """LAN adapter for Broadlink devices."""

    BRAND = "broadlink"

    def __init__(self, ir_mappings: dict[str, Any] | None = None) -> None:
        super().__init__()
        self._bl_devices: dict[str, BroadlinkDevice] = {}
        self._ir_mappings: dict[str, list[tuple[str, str, bytes, bytes]]] = {}
        self._virtual_to_remote: dict[str, tuple[str, bytes, bytes]] = {}
        self._virtual_devices: dict[str, DeviceInfo] = {}
        self._virtual_states: dict[str, bool] = {}
        self._load_ir_mappings(ir_mappings or {})

    def _load_ir_mappings(self, mappings: dict[str, Any]) -> None:
        if not isinstance(mappings, dict):
            raise ValueError("broadlink_ir_mappings must map remote IDs to mapping lists")
        for remote_id, entries in mappings.items():
            if not isinstance(remote_id, str) or not remote_id:
                raise ValueError("Broadlink IR mapping keys must be non-empty device IDs")
            if not isinstance(entries, list):
                raise ValueError(f"Broadlink IR mappings for {remote_id} must be a list")
            parsed: list[tuple[str, str, bytes, bytes]] = []
            seen_ids: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError(f"Broadlink IR mapping for {remote_id} must be an object")
                mapping_id = entry.get("id")
                name = entry.get("name")
                if (not isinstance(mapping_id, str) or not mapping_id
                        or not mapping_id.isascii()
                        or not all(char.isalnum() or char in "-_" for char in mapping_id)):
                    raise ValueError("Broadlink IR mapping id must use ASCII letters, digits, '-' or '_'")
                if mapping_id in seen_ids:
                    raise ValueError(f"Duplicate Broadlink IR mapping id {mapping_id!r} for {remote_id}")
                if not isinstance(name, str) or not name.strip():
                    raise ValueError(f"Broadlink IR mapping {mapping_id} requires a non-empty name")
                codes: list[bytes] = []
                for field in ("on", "off"):
                    value = entry.get(field)
                    if not isinstance(value, str) or not value or len(value) > 8192:
                        raise ValueError(f"Broadlink IR mapping {mapping_id}.{field} must be non-empty hex")
                    try:
                        code = bytes.fromhex(value)
                    except ValueError as exc:
                        raise ValueError(
                            f"Broadlink IR mapping {mapping_id}.{field} must be valid hex"
                        ) from exc
                    if not code:
                        raise ValueError(f"Broadlink IR mapping {mapping_id}.{field} cannot be empty")
                    codes.append(code)
                seen_ids.add(mapping_id)
                parsed.append((mapping_id, name.strip(), codes[0], codes[1]))
            self._ir_mappings[remote_id] = parsed

    def _materialize_ir_devices(self, remote: DeviceInfo) -> None:
        if remote.device_type != DeviceType.IR_REMOTE:
            # If discovery now identifies this MAC as another hardware type,
            # retire its configured virtual IR endpoints and command mappings.
            for virtual_id, virtual in list(self._virtual_devices.items()):
                if virtual.raw_metadata.get("parent_device_id") != remote.device_id:
                    continue
                self._virtual_devices.pop(virtual_id, None)
                self._virtual_to_remote.pop(virtual_id, None)
                self._virtual_states.pop(virtual_id, None)
                self._devices.pop(virtual_id, None)
            return
        for mapping_id, name, on_code, off_code in self._ir_mappings.get(remote.device_id, []):
            virtual_id = f"{remote.device_id}::ir::{mapping_id}"
            virtual = self._virtual_devices.get(virtual_id)
            if virtual is None:
                virtual = DeviceInfo(
                    brand=self.BRAND,
                    device_id=virtual_id,
                    ip=remote.ip,
                    port=remote.port,
                    model=f"{remote.model} IR mapping"[:64],
                    device_type=DeviceType.ON_OFF_LIGHT,
                    name=name,
                    raw_metadata={"virtual_ir": True, "parent_device_id": remote.device_id},
                )
                self._virtual_devices[virtual_id] = virtual
                self._devices[virtual_id] = virtual
            else:
                virtual.ip = remote.ip
                virtual.port = remote.port
                virtual.model = f"{remote.model} IR mapping"[:64]
                virtual.name = name
            self._virtual_to_remote[virtual_id] = (remote.device_id, on_code, off_code)

    def load_device(self, device: DeviceInfo) -> None:
        """Restore a previously discovered device record at adapter startup."""
        if device.brand != self.BRAND:
            raise ValueError(f"Cannot load {device.brand} record into Broadlink adapter")
        devtype = device.raw_metadata.get("devtype", 0)
        if (not isinstance(devtype, int) or isinstance(devtype, bool)
                or not 0 <= devtype <= 0xFFFF):
            raise ValueError(f"Invalid stored Broadlink devtype for {device.device_id}")
        if device.session_key and len(device.session_key) != 16:
            raise ValueError(f"Invalid stored Broadlink session key for {device.device_id}")
        if device.auth_token and len(device.auth_token) != 4:
            raise ValueError(f"Invalid stored Broadlink device ID for {device.device_id}")
        self._devices[device.device_id] = device
        bl = BroadlinkDevice(device)
        bl.devtype = devtype
        # Cached credentials supplied by callers are not trusted as live after
        # a process restart. Discovery will perform a fresh LAN handshake.
        self._bl_devices[device.device_id] = bl
        self._materialize_ir_devices(device)
        self._schedule_poll(device.device_id)

    def _schedule_poll(self, device_id: str) -> None:
        task_name = f"broadlink-poll:{device_id}"
        if self._running and not any(
            not task.done() and task.get_name() == task_name for task in self._tasks
        ):
            self._tasks.append(asyncio.create_task(self._poll_loop(device_id), name=task_name))

    async def start(self) -> None:
        await super().start()
        for device_id in self._bl_devices:
            self._schedule_poll(device_id)

    async def _poll_loop(self, device_id: str) -> None:
        while self._running:
            try:
                await self.publish_state(device_id, await self.get_state(device_id))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("Broadlink state poll failed for %s", device_id, exc_info=True)
            await asyncio.sleep(POLL_INTERVAL)

    async def discover(self, timeout: float | None = None) -> list[DeviceInfo]:
        """
        Send UDP discovery broadcast and collect responses.

        Discovery packet (0x30 bytes) with local date, reversed IP,
        command 0x06, and checksum fields from the LAN protocol.
        """
        timeout = self.DISCOVERY_TIMEOUT if timeout is None else max(0.0, timeout)
        found: list[DeviceInfo] = []

        loop = asyncio.get_running_loop()
        responses: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(maxsize=256)

        class DiscoveryProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                if not responses.full():
                    responses.put_nowait((data, addr))

        transports: list[tuple[asyncio.DatagramTransport, bytes, str]] = []
        try:
            interfaces = get_ipv4_broadcast_interfaces()
            for local_ip, broadcast_ip in interfaces:
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        DiscoveryProtocol,
                        local_addr=(local_ip, 0),
                        family=socket.AF_INET,
                        allow_broadcast=True,
                    )
                except OSError:
                    logger.debug("Could not open Broadlink discovery socket on %s", local_ip,
                                 exc_info=True)
                    continue
                source_port = transport.get_extra_info("sockname")[1]
                packet = self._build_discovery_packet(local_ip, source_port)
                transports.append((transport, packet, broadcast_ip))
            if not transports:
                raise OSError("No IPv4 interface is available for Broadlink discovery")

            deadline = loop.time() + timeout
            next_send = loop.time()
            seen: set[str] = set()
            while True:
                now = loop.time()
                if now >= deadline:
                    break
                if now >= next_send:
                    for transport, packet, broadcast_ip in transports:
                        transport.sendto(packet, (broadcast_ip, 80))
                    next_send = now + 1.0
                try:
                    data, addr = await asyncio.wait_for(
                        responses.get(), timeout=min(deadline - now, next_send - now)
                    )
                except asyncio.TimeoutError:
                    continue
                try:
                    device_info = self._parse_discovery_response(data, addr)
                    if device_info:
                        if device_info.device_id in seen:
                            continue
                        seen.add(device_info.device_id)
                        devtype = int.from_bytes(data[0x34:0x36], "little")
                        previous = self._devices.get(device_info.device_id)
                        if previous is not None:
                            bl = self._bl_devices[device_info.device_id]
                            async with bl.lock:
                                previous.ip = device_info.ip
                                previous.port = device_info.port
                                previous.model = device_info.model
                                # The discovery devtype map is authoritative; clear
                                # stale capabilities when a previously known device
                                # now reports an unsupported hardware type.
                                previous.device_type = device_info.device_type
                                previous.name = device_info.name or previous.name
                                previous.raw_metadata.update(device_info.raw_metadata)
                                device_info = previous
                                bl.info = device_info
                                bl.devtype = devtype
                        else:
                            self._devices[device_info.device_id] = device_info
                            bl = BroadlinkDevice(device_info)
                            bl.devtype = devtype
                            self._bl_devices[device_info.device_id] = bl
                        self._schedule_poll(device_info.device_id)
                        self._materialize_ir_devices(device_info)
                        found.append(device_info)
                        logger.info(
                            "Discovered Broadlink device: %s (%s) at %s",
                            device_info.device_id,
                            device_info.model,
                            device_info.ip,
                        )
                except Exception:
                    logger.debug("Failed to parse discovery response from %s", addr)
        except asyncio.CancelledError:
            raise
        finally:
            for transport, _, _ in transports:
                transport.close()

        return found

    async def authenticate(self, device: DeviceInfo, *, force: bool = False) -> bool:
        """
        Perform Broadlink auth handshake.

        Sends command 0x0065 with the initial auth marker and device label;
        the device responds with its numeric ID and session AES key.
        """
        bl = self._bl_devices.get(device.device_id)
        if not bl:
            return False
        async with bl.auth_lock:
            return await self._authenticate_locked(bl, device, force=force)

    def is_online(self, device_id: str) -> bool:
        """Return whether this process has confirmed a live Broadlink session."""
        bl = self._bl_devices.get(device_id)
        return bool(bl and bl.authenticated and bl.online)

    async def _authenticate_locked(
        self, bl: BroadlinkDevice, device: DeviceInfo, *, force: bool
    ) -> bool:
        if bl.authenticated and not force:
            return True

        # Keep reset, handshake, and key replacement atomic with respect to
        # commands. A packet sent in the gap could otherwise use the default
        # key with the previous session's device ID (or vice versa).
        async with bl.lock:
            if force:
                bl.authenticated = False
                bl.online = False
                bl.key = DEFAULT_KEY
                bl.device_id_int = 0
            elif bl.authenticated:
                return True

            # Build auth payload (0x50 = 80 bytes).
            auth_payload = bytearray(0x50)
            auth_payload[0x04:0x14] = b"1" * 16
            auth_payload[0x1E] = 0x01
            auth_payload[0x2D] = 0x01
            name = b"Matter Bridge"
            auth_payload[0x30:0x30 + len(name)] = name

            response = await self._send_packet_locked(bl, 0x0065, auth_payload)
            if response is None:
                return False

            try:
                device_id_int, new_key = parse_auth_response(response, bl.key)
                bl.device_id_int = device_id_int
                bl.key = new_key
                bl.authenticated = True
                bl.session_error = False

                # Store session key in device info.
                device.session_key = new_key
                device.auth_token = struct.pack("<I", device_id_int)

                logger.info(
                    "Authenticated Broadlink %s (id=%d)", device.device_id, device_id_int
                )
                return True

            except Exception:
                logger.exception("Auth failed for %s", device.device_id)
                return False

    async def get_state(self, device_id: str) -> DeviceState:
        """Query device state (SP2/SP3 power state, A1 sensors)."""
        virtual = self._virtual_to_remote.get(device_id)
        if virtual is not None:
            remote_id = virtual[0]
            bl = self._bl_devices.get(remote_id)
            return DeviceState(
                online=bool(bl and bl.online),
                on=self._virtual_states.get(device_id),
                raw={"state_source": "last_ir_command"},
            )

        bl = self._bl_devices.get(device_id)
        device = self._devices.get(device_id)
        if not bl or not device:
            return DeviceState(online=False)

        dt = device.device_type

        if dt == DeviceType.ON_OFF_PLUG:
            return await self._get_sp_state(bl)
        elif dt == DeviceType.TEMPERATURE_SENSOR:
            return await self._get_a1_state(bl)
        elif dt == DeviceType.IR_REMOTE:
            if bl.devtype in _RM4_SENSOR_DEVTYPES:
                return await self._get_rm4_sensor_state(bl)
            return await self._get_remote_state(bl)
        else:
            return DeviceState(online=bl.online)

    async def set_state(self, device_id: str, **kwargs: Any) -> bool:
        """Control device (SP2 on/off, RM send IR data)."""
        virtual = self._virtual_to_remote.get(device_id)
        if virtual is not None:
            if set(kwargs) != {"on"} or not isinstance(kwargs["on"], bool):
                return False
            remote_id, on_code, off_code = virtual
            bl = self._bl_devices.get(remote_id)
            if not bl:
                await self.publish_state(device_id, DeviceState(
                    online=False,
                    on=self._virtual_states.get(device_id),
                    raw={"state_source": "last_ir_command"},
                ))
                return False
            sent = await self._send_ir_data(bl, on_code if kwargs["on"] else off_code)
            if sent:
                self._virtual_states[device_id] = kwargs["on"]
            elif not bl.online:
                await self.publish_state(device_id, DeviceState(online=False))
            return sent

        bl = self._bl_devices.get(device_id)
        if not bl:
            await self.publish_state(device_id, DeviceState(online=False))
            return False

        device = self._devices.get(device_id)
        if not device:
            return False

        if (device.device_type == DeviceType.ON_OFF_PLUG
                and set(kwargs) == {"on"}
                and isinstance(kwargs["on"], bool)):
            sent = await self._set_sp_power(bl, kwargs["on"])
            if not sent and not bl.online:
                await self.publish_state(device_id, DeviceState(online=False))
            return sent

        if (device.device_type == DeviceType.IR_REMOTE
                and set(kwargs) == {"ir_data"}
                and isinstance(kwargs.get("ir_data"), (bytes, bytearray))
                and bool(kwargs["ir_data"])):
            sent = await self._send_ir_data(bl, kwargs["ir_data"])
            if not sent and not bl.online:
                await self.publish_state(device_id, DeviceState(online=False))
            return sent

        return False

    # --- SP2/SP3 Smart Plug ---

    async def _get_sp_state(self, bl: BroadlinkDevice) -> DeviceState:
        """Query SP2/SP3 power state."""
        payload = bytearray(16)
        payload[0] = 0x01  # Check power command
        response = await self._send_packet_with_reauth(bl, 0x006A, payload)
        if response is None:
            return DeviceState(online=bl.online)
        try:
            decrypted = self._decrypt_response_payload(response, bl.key, 5)
            # Power state at byte 0x04
            power = decrypted[0x04]
            if bl.devtype in _SP3_NIGHTLIGHT_DEVTYPES:
                return DeviceState(
                    online=True,
                    on=bool(power & 0x01),
                    raw={"nightlight": bool(power & 0x02)},
                )
            is_on = True if power == 1 else False if power == 0 else None
            return DeviceState(online=True, on=is_on)
        except Exception:
            logger.debug("Malformed Broadlink plug-state response from %s", bl.info.device_id,
                         exc_info=True)
            return DeviceState(online=bl.online)

    async def _set_sp_power(self, bl: BroadlinkDevice, on: bool) -> bool:
        """Set SP2/SP3 power on/off."""
        payload = bytearray(16)
        payload[0] = 0x02  # Set power command
        if bl.devtype in _SP3_NIGHTLIGHT_DEVTYPES:
            state = await self._get_sp_state(bl)
            if not state.online or not isinstance(state.raw.get("nightlight"), bool):
                return False
            payload[4] = (0x02 if state.raw["nightlight"] else 0x00) | int(on)
        else:
            payload[4] = 0x01 if on else 0x00
        response = await self._send_packet_with_reauth(bl, 0x006A, payload)
        return response is not None

    # --- A1 Environment Sensor ---

    async def _get_a1_state(self, bl: BroadlinkDevice) -> DeviceState:
        """Query A1 sensor data."""
        payload = b"\x01"
        response = await self._send_packet_with_reauth(bl, 0x006A, payload)
        if response is None:
            return DeviceState(online=bl.online)
        try:
            decrypted = self._decrypt_response_payload(response, bl.key, 0x0D)
            temp = (decrypted[0x04] * 10 + decrypted[0x05]) / 10.0
            humidity = (decrypted[0x06] * 10 + decrypted[0x07]) / 10.0
            light_raw = decrypted[0x08]
            air_quality_raw = decrypted[0x0A]
            noise_raw = decrypted[0x0C]
            # These are Broadlink ordinal categories, not lux, ppm, or dB.
            # Preserve the wire values and provide labels for local diagnostics.
            light_levels = ("dark", "dim", "normal", "bright")
            air_quality_levels = ("excellent", "good", "normal", "bad")
            noise_levels = ("quiet", "normal", "noisy")
            return DeviceState(
                online=True,
                temperature=temp,
                humidity=humidity,
                raw={
                    "light": light_raw,
                    "light_level": light_levels[light_raw]
                    if light_raw < len(light_levels) else None,
                    "air_quality": air_quality_raw,
                    "air_quality_level": air_quality_levels[air_quality_raw]
                    if air_quality_raw < len(air_quality_levels) else None,
                    "noise": noise_raw,
                    "noise_level": noise_levels[noise_raw]
                    if noise_raw < len(noise_levels) else None,
                },
            )
        except Exception:
            logger.debug("Malformed Broadlink A1 response from %s", bl.info.device_id,
                         exc_info=True)
            return DeviceState(online=bl.online)

    async def _get_rm4_sensor_state(self, bl: BroadlinkDevice) -> DeviceState:
        """Read temperature/humidity from an attached RM4 sensor accessory."""
        response = await self._send_packet_with_reauth(
            bl, 0x006A, self._pack_device_command(bl, 0x24)
        )
        if response is None:
            return DeviceState(online=bl.online)
        try:
            data = self._decrypt_device_response(bl, response, minimum_length=4)
            temp_whole, temp_fraction = struct.unpack_from("<bb", data)
            temperature = temp_whole + temp_fraction / 100.0
            humidity = data[2] + data[3] / 100.0
            return DeviceState(online=True, temperature=temperature, humidity=humidity)
        except (IndexError, ValueError, struct.error):
            logger.debug("Malformed Broadlink RM4 sensor response from %s", bl.info.device_id,
                         exc_info=True)
            return DeviceState(online=bl.online)

    async def _get_remote_state(self, bl: BroadlinkDevice) -> DeviceState:
        """Probe an RM remote with its local information command."""
        response = await self._send_packet_with_reauth(
            bl, 0x006A, self._pack_device_command(bl, 0x01)
        )
        return DeviceState(online=response is not None and bl.online)

    @staticmethod
    def _pack_device_command(bl: BroadlinkDevice, command: int, data: bytes = b"") -> bytes:
        if bl.devtype in _NEW_COMMAND_PROTOCOL_DEVTYPES:
            return struct.pack("<HI", len(data) + 4, command) + data
        return struct.pack("<I", command) + data

    @staticmethod
    def _decrypt_device_response(
        bl: BroadlinkDevice, response: bytes, minimum_length: int = 0
    ) -> bytes:
        if len(response) <= 0x38:
            raise ValueError("Broadlink response has no encrypted payload")
        decrypted = decrypt(response[0x38:], bl.key, bl.iv)
        if bl.devtype in _NEW_COMMAND_PROTOCOL_DEVTYPES:
            if len(decrypted) < 6:
                raise ValueError("Broadlink response has no new-protocol command header")
            packet_length = struct.unpack_from("<H", decrypted)[0]
            if packet_length < 4 or packet_length + 2 > len(decrypted):
                raise ValueError("Broadlink response has an invalid new-protocol length")
            data = decrypted[6:packet_length + 2]
        else:
            data = decrypted[4:]
        if len(data) < minimum_length:
            raise ValueError(
                f"Broadlink response data is too short: expected at least {minimum_length} bytes"
            )
        return data

    # --- RM IR Blaster ---

    async def _send_ir_data(self, bl: BroadlinkDevice, ir_data: bytes) -> bool:
        """Send IR data via RM device."""
        if not isinstance(ir_data, (bytes, bytearray)) or len(ir_data) > 0xFFFF:
            return False
        async with bl.ir_lock:
            return await self._send_ir_data_locked(bl, ir_data)

    async def _send_ir_data_locked(self, bl: BroadlinkDevice, ir_data: bytes) -> bool:
        payload = self._pack_device_command(bl, 0x02, bytes(ir_data))
        response = await self._send_packet_with_reauth(bl, 0x006A, payload)
        return response is not None

    async def _send_packet_with_reauth(
        self, bl: BroadlinkDevice, command: int, payload: bytes | bytearray
    ) -> bytes | None:
        """Serialize a command with any required session renewal and retry."""
        async with bl.auth_lock:
            if not bl.authenticated or not bl.online:
                if not await self._authenticate_locked(
                    bl, bl.info, force=bl.authenticated
                ):
                    return None
            response = await self._send_packet(bl, command, payload)
            if response is not None or (not bl.session_error and bl.online):
                return response
            if not await self._authenticate_locked(bl, bl.info, force=True):
                return None
            return await self._send_packet(bl, command, payload)

    async def learn_ir(self, device_id: str) -> bytes | None:
        """Enter IR learning mode and capture a code."""
        bl = self._bl_devices.get(device_id)
        if not bl:
            return None
        async with bl.ir_lock:
            return await self._learn_ir_locked(bl)

    async def _learn_ir_locked(self, bl: BroadlinkDevice) -> bytes | None:
        # Enter learning mode
        payload = self._pack_device_command(bl, 0x03)
        response = await self._send_packet_with_reauth(bl, 0x006A, payload)
        if response is None:
            return None

        # Poll for learned data
        for _ in range(30):  # 30 attempts, ~100ms apart
            await asyncio.sleep(0.1)
            check_payload = self._pack_device_command(bl, 0x04)
            response = await self._send_packet_with_reauth(bl, 0x006A, check_payload)
            if response and len(response) > 0x38:
                try:
                    decrypted = self._decrypt_device_response(bl, response)
                except Exception:
                    logger.debug(
                        "Malformed IR learning response from %s",
                        bl.info.device_id,
                        exc_info=True,
                    )
                    continue
                captured = bytes(decrypted)
                terminator = captured.rfind(b"\x00\x0d\x05")
                if terminator >= 0:
                    captured = captured[:terminator + 3]
                else:
                    captured = captured.rstrip(b"\x00")
                if any(captured):
                    return captured

        return None

    @staticmethod
    def _decrypt_response_payload(response: bytes, key: bytes, minimum_length: int) -> bytes:
        """Decrypt a response body and enforce the command's minimum structure."""
        if len(response) <= 0x38:
            raise ValueError("Broadlink response has no encrypted payload")
        decrypted = decrypt(response[0x38:], key)
        if len(decrypted) < minimum_length:
            raise ValueError(
                f"Broadlink response payload is too short: expected at least {minimum_length} bytes"
            )
        return decrypted

    # --- Packet Transport ---

    async def _send_packet(
        self,
        bl: BroadlinkDevice,
        command: int,
        payload: bytes | bytearray,
    ) -> bytes | None:
        """Send an encrypted packet and wait for response."""
        async with bl.lock:
            return await self._send_packet_locked(bl, command, payload)

    async def _send_packet_locked(
        self, bl: BroadlinkDevice, command: int, payload: bytes | bytearray
    ) -> bytes | None:
        """Serialize commands because Broadlink correlates responses by counter."""
        bl.session_error = False
        bl.count = ((bl.count + 1) | 0x8000) & 0xFFFF

        # Parse MAC
        try:
            mac_str = bl.info.mac.replace(":", "").replace("-", "")
            mac_bytes = bytes.fromhex(mac_str) if mac_str else b"\x00" * 6
        except ValueError:
            logger.error("Invalid MAC address for Broadlink device %s", bl.info.device_id)
            return None

        header = build_header(
            devtype=bl.devtype,
            command=command,
            count=bl.count,
            mac=mac_bytes,
            device_id=bl.device_id_int,
        )

        encrypted_payload = encrypt(bytes(payload), bl.key, bl.iv)
        packet = finalize_packet(header, encrypted_payload, bytes(payload))

        loop = asyncio.get_running_loop()
        future: asyncio.Future[bytes] = loop.create_future()

        class ResponseProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                if addr[0] == bl.info.ip and not future.done():
                    future.set_result(data)

        transport, _ = await loop.create_datagram_endpoint(
            ResponseProtocol,
            local_addr=("0.0.0.0", 0),
            family=socket.AF_INET,
        )

        try:
            transport.sendto(packet, (bl.info.ip, bl.info.port or 80))
            response = await asyncio.wait_for(future, timeout=self.COMMAND_TIMEOUT)
            try:
                validate_response(response)
            except ValueError as exc:
                bl.session_error = str(exc).startswith("Broadlink device returned error")
                bl.online = bl.session_error
                logger.warning("Invalid Broadlink response from %s: %s", bl.info.device_id, exc)
                return None
            bl.online = True
            response_count = struct.unpack_from("<H", response, 0x28)[0]
            if response_count != bl.count:
                logger.warning(
                    "Broadlink response counter mismatch for %s: expected %d, got %d",
                    bl.info.device_id,
                    bl.count,
                    response_count,
                )
                bl.online = False
                return None
            return response
        except asyncio.TimeoutError:
            bl.online = False
            logger.warning("Timeout waiting for response from %s", bl.info.device_id)
            return None
        except OSError as exc:
            bl.online = False
            logger.warning("UDP error for %s: %s", bl.info.device_id, exc)
            return None
        finally:
            transport.close()

    def _build_discovery_packet(
        self, local_ip: str | None = None, source_port: int = 0
    ) -> bytes:
        """Build the UDP discovery broadcast packet."""
        now = datetime.datetime.now().astimezone()

        packet = bytearray(0x30)
        offset = now.utcoffset()
        tz_offset = int(offset.total_seconds() / 3600) if offset else 0
        struct.pack_into("<i", packet, 0x08, tz_offset)

        # Date/time
        packet[0x0C] = now.year & 0xFF
        packet[0x0D] = (now.year >> 8) & 0xFF
        packet[0x0E] = now.minute
        packet[0x0F] = now.hour
        packet[0x10] = now.year % 100
        packet[0x11] = now.isoweekday()
        packet[0x12] = now.day
        packet[0x13] = now.month

        # Local IP address (reversed)
        local_ip = local_ip or get_local_ipv4()
        packet[0x18:0x1C] = socket.inet_aton(local_ip)[::-1]
        struct.pack_into("<H", packet, 0x1C, source_port)

        # Command: discover (0x0006)
        packet[0x26] = 0x06

        # Checksum
        struct.pack_into("<H", packet, 0x20, (0xBEAF + sum(packet)) & 0xFFFF)

        return bytes(packet)

    def _parse_discovery_response(
        self, data: bytes, addr: tuple[str, int]
    ) -> DeviceInfo | None:
        """Parse the fixed Broadlink discovery header; ignore malformed datagrams."""
        if (len(data) < 0x80 or not is_lan_unicast_address(addr[0])
                or type(addr[1]) is not int or not 1 <= addr[1] <= 65535):
            return None
        # Discovery responses include a 0x10-byte prefix before the command
        # header; the response devtype and MAC therefore use these offsets.
        devtype = struct.unpack_from("<H", data, 0x34)[0]
        # Do not infer a plug from a broad devtype range. Unknown Broadlink
        # models must stay non-controllable until their type is identified.
        model, device_type = _DEVTYPE_MAP.get(
            devtype, (f"Unknown 0x{devtype:04x}", DeviceType.UNKNOWN)
        )
        mac_bytes = data[0x3A:0x40][::-1]
        invalid_mac = (
            len(mac_bytes) != 6
            or mac_bytes in (b"\x00" * 6, b"\xff" * 6)
            or bool(mac_bytes[0] & 1)
        )
        if invalid_mac:
            return None
        mac = ":".join(f"{byte:02x}" for byte in mac_bytes)
        device_id = f"{mac}:{devtype:04x}"
        # The device name occupies the fixed field before the lock byte.
        name = data[0x40:0x7F].split(b"\x00", 1)[0].decode("utf-8", "replace")
        return DeviceInfo(
            brand=self.BRAND,
            device_id=device_id,
            ip=addr[0],
            port=addr[1],
            mac=mac,
            model=model,
            device_type=device_type,
            name=name,
            raw_metadata={
                "devtype": devtype,
                "response_length": len(data),
                "name": name,
                "locked": bool(data[0x7F]),
            },
        )

