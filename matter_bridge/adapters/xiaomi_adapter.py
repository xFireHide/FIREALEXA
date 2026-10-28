"""Local Xiaomi miIO adapter for devices with a locally provisioned token."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import struct
import time
from typing import Any

from matter_bridge.core.base_adapter import BaseAdapter, DeviceInfo, DeviceState, DeviceType
from matter_bridge.crypto.xiaomi_crypto import (
    HELLO_PACKET,
    build_packet,
    parse_hello_response,
    parse_response,
)
from matter_bridge.discovery.network import (
    get_ipv4_broadcast_interfaces,
    is_lan_unicast_address,
)

logger = logging.getLogger(__name__)
MIIO_PORT = 54321
POLL_INTERVAL = 10.0


class XiaomiAdapter(BaseAdapter):
    """miIO UDP discovery and JSON-RPC control; token material stays local."""

    BRAND = "xiaomi"

    @staticmethod
    def _is_valid_device_id(device_id: object) -> bool:
        return (
            isinstance(device_id, str)
            and device_id.isascii()
            and device_id.isdecimal()
            and len(device_id) <= 10
            and 1 <= int(device_id) <= 0xFFFFFFFF
            and str(int(device_id)) == device_id
        )

    def __init__(self, tokens: dict[str, str] | None = None) -> None:
        super().__init__()
        self._tokens: dict[str, bytes] = {}
        for device_id, token in (tokens or {}).items():
            if not self._is_valid_device_id(device_id):
                raise ValueError(
                    f"Xiaomi miIO device ID {device_id!r} must be a canonical "
                    "unsigned 32-bit decimal ID"
                )
            if not isinstance(token, str):
                raise ValueError(f"Xiaomi token for device {device_id} must be a string")
            normalized = token.removeprefix("0x").replace(":", "")
            if len(normalized) != 32 or any(
                character not in "0123456789abcdefABCDEF" for character in normalized
            ):
                raise ValueError(
                    f"Xiaomi token for device {device_id} must contain 32 hexadecimal characters"
                )
            try:
                parsed = bytes.fromhex(normalized)
            except ValueError as exc:
                raise ValueError(
                    f"Xiaomi token for device {device_id} must be hexadecimal"
                ) from exc
            if len(parsed) != 16:
                raise ValueError(f"Xiaomi token for device {device_id} must be exactly 16 bytes")
            self._tokens[device_id] = parsed
        self._stamps: dict[str, tuple[int, float]] = {}
        self._packet_ids: dict[str, int] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def load_device(self, device: DeviceInfo) -> None:
        if device.brand != self.BRAND:
            raise ValueError(f"Cannot load {device.brand} record into Xiaomi adapter")
        if not self._is_valid_device_id(device.device_id):
            raise ValueError(f"Invalid stored Xiaomi miIO device ID {device.device_id!r}")
        if device.auth_token and len(device.auth_token) != 16:
            raise ValueError(f"Invalid stored Xiaomi token for device {device.device_id}")
        self._devices[device.device_id] = device
        if device.auth_token:
            self._tokens.setdefault(device.device_id, device.auth_token)
        stamp = device.raw_metadata.get("stamp")
        if isinstance(stamp, int):
            self._stamps[device.device_id] = (stamp, time.monotonic())
        self._schedule_poll(device.device_id)

    def _schedule_poll(self, device_id: str) -> None:
        task_name = f"xiaomi-poll:{device_id}"
        if self._running and not any(
            not task.done() and task.get_name() == task_name for task in self._tasks
        ):
            self._tasks.append(asyncio.create_task(self._poll_loop(device_id), name=task_name))

    async def start(self) -> None:
        await super().start()
        for device_id in self._devices:
            self._schedule_poll(device_id)

    async def _poll_loop(self, device_id: str) -> None:
        while self._running:
            try:
                await self.publish_state(device_id, await self.get_state(device_id))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("miIO poll failed for %s", device_id, exc_info=True)
            await asyncio.sleep(POLL_INTERVAL)

    async def discover(self, timeout: float | None = None) -> list[DeviceInfo]:
        timeout = self.DISCOVERY_TIMEOUT if timeout is None else timeout
        loop = asyncio.get_running_loop()
        found: dict[str, DeviceInfo] = {}
        queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(maxsize=256)

        class Protocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                if not queue.full():
                    queue.put_nowait((data, addr))

        transports: list[tuple[asyncio.DatagramTransport, str]] = []
        try:
            for local_ip, broadcast_ip in get_ipv4_broadcast_interfaces():
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        Protocol,
                        local_addr=(local_ip, 0),
                        family=socket.AF_INET,
                        allow_broadcast=True,
                    )
                except OSError:
                    logger.debug("Could not open miIO discovery socket on %s", local_ip,
                                 exc_info=True)
                    continue
                transports.append((transport, broadcast_ip))
            if not transports:
                raise OSError("No IPv4 interface is available for miIO discovery")
            # miIO discovery is connectionless and a single broadcast can be
            # lost on busy Wi-Fi networks. Match the reference client's three
            # HELLO probes; duplicate replies are deduplicated by device ID.
            for transport, broadcast_ip in transports:
                for _ in range(3):
                    transport.sendto(HELLO_PACKET, (broadcast_ip, MIIO_PORT))
            deadline = loop.time() + timeout
            while True:
                try:
                    packet, addr = await asyncio.wait_for(
                        queue.get(), max(0.0, deadline - loop.time())
                    )
                except asyncio.TimeoutError:
                    break
                try:
                    device_id, stamp, _ = parse_hello_response(packet)
                    if device_id == 0 or not is_lan_unicast_address(addr[0]):
                        continue
                    key = str(device_id)
                    token = self._tokens.get(key, b"")
                    discovered = DeviceInfo(
                        brand=self.BRAND,
                        device_id=key,
                        ip=addr[0],
                        port=MIIO_PORT,
                        device_type=DeviceType.UNKNOWN,
                        model="Xiaomi miIO (model unknown)",
                        name=f"Xiaomi {key}",
                        auth_token=token,
                        raw_metadata={"device_id": device_id, "stamp": stamp,
                                      "token_configured": bool(token)},
                    )
                    lock = self._locks.setdefault(key, asyncio.Lock())
                    async with lock:
                        device = self._devices.get(key)
                        if device is None:
                            device = discovered
                            self._devices[key] = device
                        else:
                            # _rpc holds this lock through its UDP exchange.
                            # Keep its destination stable until the response
                            # has been accepted or the request has timed out.
                            device.ip = discovered.ip
                            device.port = discovered.port
                            device.raw_metadata.update(discovered.raw_metadata)
                            if token:
                                device.auth_token = token
                        self._stamps[key] = (stamp, time.monotonic())
                    self._schedule_poll(key)
                    found[key] = device
                except (ValueError, struct.error, IndexError):
                    logger.debug("Ignoring malformed miIO discovery response from %s", addr)
        except asyncio.CancelledError:
            raise
        finally:
            for transport, _ in transports:
                transport.close()
        return list(found.values())

    async def authenticate(self, device: DeviceInfo) -> bool:
        token = self._tokens.get(device.device_id) or device.auth_token
        if len(token) != 16:
            return False
        device.auth_token = token
        try:
            response = await self._rpc(device.device_id, "miIO.info", [])
        except asyncio.CancelledError:
            raise
        except (OSError, asyncio.TimeoutError, ValueError, struct.error):
            logger.debug("miIO authentication failed for %s", device.device_id, exc_info=True)
            return False
        if not isinstance(response, dict):
            return False
        device.model = str(response.get("model") or device.model)
        device.firmware = str(response.get("fw_ver") or "")
        device.mac = str(response.get("mac") or "")
        device.name = device.model
        model = device.model.lower()
        if any(marker in model for marker in (".plug", "plug.", "powerstrip")):
            device.device_type = DeviceType.ON_OFF_PLUG
        elif any(marker in model for marker in (".light", "light.", "bulb")):
            device.device_type = DeviceType.ON_OFF_LIGHT
        else:
            # A successful info response with a different/unsupported model
            # must not retain a stale on/off capability from an earlier scan.
            device.device_type = DeviceType.UNKNOWN
        device.raw_metadata["info"] = response
        return True

    async def get_state(self, device_id: str) -> DeviceState:
        device = self._devices.get(device_id)
        if not device or len(device.auth_token) != 16:
            return DeviceState(online=False)
        try:
            result = await self._rpc(device_id, "get_prop", ["power"])
            if not isinstance(result, list) or not result:
                return DeviceState(online=False)
            raw = {"properties": result}
            value = result[0]
            if value in ("on", True, 1):
                on = True
            elif value in ("off", False, 0):
                on = False
            else:
                on = None
            return DeviceState(online=True, on=on, raw=raw)
        except (OSError, asyncio.TimeoutError, ValueError, json.JSONDecodeError):
            logger.debug("miIO state request failed for %s", device_id, exc_info=True)
            return DeviceState(online=False)

    async def set_state(self, device_id: str, **kwargs: Any) -> bool:
        device = self._devices.get(device_id)
        if (
            set(kwargs) != {"on"}
            or not isinstance(kwargs["on"], bool)
            or device is None
            or device.device_type not in {DeviceType.ON_OFF_PLUG, DeviceType.ON_OFF_LIGHT}
        ):
            return False
        try:
            result = await self._rpc(
                device_id, "set_power", ["on" if kwargs["on"] else "off"]
            )
            return result == ["ok"] or result == "ok"
        except (OSError, asyncio.TimeoutError, ValueError, json.JSONDecodeError):
            logger.debug("miIO command failed for %s", device_id, exc_info=True)
            return False

    async def _rpc(self, device_id: str, method: str, params: list[Any]) -> Any:
        device = self._devices.get(device_id)
        token = self._tokens.get(device_id) or (device.auth_token if device else b"")
        if device is None or len(token) != 16:
            raise ValueError("Device or local 16-byte token is unavailable")
        lock = self._locks.setdefault(device_id, asyncio.Lock())
        async with lock:
            packet_id = self._packet_ids.get(device_id, 0) + 1
            self._packet_ids[device_id] = packet_id
            payload = json.dumps(
                {"id": packet_id, "method": method, "params": params},
                separators=(",", ":"),
            ).encode()
            stamp_base, monotonic_base = self._stamps.get(
                device_id, (0, time.monotonic())
            )
            stamp = stamp_base + max(0, int(time.monotonic() - monotonic_base))
            packet = build_packet(token, int(device_id), payload, stamp=stamp)
            loop = asyncio.get_running_loop()
            future: asyncio.Future[bytes] = loop.create_future()

            class Protocol(asyncio.DatagramProtocol):
                def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                    if addr[0] == device.ip and not future.done():
                        future.set_result(data)

            transport, _ = await loop.create_datagram_endpoint(
                Protocol, local_addr=("0.0.0.0", 0), family=socket.AF_INET
            )
            try:
                transport.sendto(packet, (device.ip, device.port or MIIO_PORT))
                response = await asyncio.wait_for(future, self.COMMAND_TIMEOUT)
            finally:
                transport.close()
            response_device_id, response_stamp, plaintext = parse_response(response, token)
            if response_device_id != int(device_id):
                raise ValueError(
                    "miIO response device ID mismatch: "
                    f"expected {device_id}, got {response_device_id}"
                )
            if response_stamp:
                self._stamps[device_id] = (response_stamp, time.monotonic())
            decoded = json.loads(plaintext)
            if not isinstance(decoded, dict) or "error" in decoded:
                raise ValueError(f"miIO command returned an error: {decoded!r}")
            response_id = decoded.get("id")
            if (not isinstance(response_id, int) or isinstance(response_id, bool)
                    or response_id != packet_id):
                raise ValueError(
                    f"miIO response ID mismatch: expected {packet_id}, got {response_id!r}"
                )
            return decoded.get("result")
