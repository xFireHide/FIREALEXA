"""
eWeLink / Sonoff LAN adapter.

Discovery: mDNS service _ewelink._tcp.local
Control: HTTP POST to http://<ip>:8081/zeroconf/<command>
Encryption: AES-128-CBC with MD5(apikey)
State: mDNS TXT record updates + HTTP polling
"""

from __future__ import annotations

import asyncio
import colorsys
import json
import logging
import time
from typing import Any
from urllib.parse import quote

import aiohttp
from zeroconf import ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

from matter_bridge.core.base_adapter import (
    BaseAdapter,
    DeviceInfo,
    DeviceState,
    DeviceType,
)
from matter_bridge.crypto.ewelink_crypto import decrypt_payload, encrypt_payload
from matter_bridge.discovery.network import is_lan_unicast_address
from matter_bridge.adapters.ewelink_protocol import parse_state_response, successful_response

logger = logging.getLogger(__name__)

MDNS_SERVICE = "_ewelink._tcp.local."
DEFAULT_PORT = 8081
POLL_INTERVAL = 10.0  # seconds
MAX_RESPONSE_BYTES = 1024 * 1024


# Map eWeLink UIID (device model IDs) to our DeviceType
_UIID_MAP: dict[int, DeviceType] = {
    1: DeviceType.ON_OFF_PLUG,      # BASIC
    2: DeviceType.ON_OFF_PLUG,      # S20
    5: DeviceType.ON_OFF_PLUG,      # S31 (power metering)
    6: DeviceType.ON_OFF_PLUG,      # BASIC (v2)
    14: DeviceType.ON_OFF_PLUG,     # BASIC (v3)
    15: DeviceType.THERMOSTAT,      # TH10/TH16
    22: DeviceType.COLOR_LIGHT,     # B1 color temperature and RGB light
    28: DeviceType.RF_REMOTE,       # RF Bridge; child RF controls are not mapped yet
    36: DeviceType.DIMMABLE_LIGHT,  # KING-M4 dimmer
    44: DeviceType.DIMMABLE_LIGHT,  # D1 dimmer (brightness only)
    59: DeviceType.COLOR_LIGHT,     # L1 Light
    77: DeviceType.ON_OFF_PLUG,     # Micro (single channel)
    78: DeviceType.ON_OFF_PLUG,     # Micro (single channel v2)
    103: DeviceType.ON_OFF_PLUG,    # BASIC R3
    104: DeviceType.ON_OFF_PLUG,    # BASIC R3 v2
    107: DeviceType.ON_OFF_PLUG,    # BASIC R4
    126: DeviceType.ON_OFF_PLUG,    # DUALR3
    182: DeviceType.ON_OFF_PLUG,    # MINI R4
}


def _is_dualr3(device: DeviceInfo) -> bool:
    uiid = device.raw_metadata.get("type")
    return (
        device.brand == "ewelink"
        and (
            device.model in {"UIID_126", "DUALR3"}
            or uiid == "126"
            or (type(uiid) is int and uiid == 126)
        )
    )


def _ewelink_uiid(device: DeviceInfo) -> int | None:
    value = device.raw_metadata.get("type")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _rgb_from_hs(hue: float, saturation: float, brightness: int = 100) -> tuple[int, int, int]:
    red, green, blue = colorsys.hsv_to_rgb(
        (hue % 360) / 360,
        max(0.0, min(100.0, saturation)) / 100,
        max(0, min(100, brightness)) / 100,
    )
    return tuple(round(channel * 255) for channel in (red, green, blue))


def _color_brightness(requested: int | None, cached: DeviceState | None) -> int:
    if requested is not None:
        return requested
    if cached is not None and cached.brightness is not None and cached.brightness > 0:
        return cached.brightness
    return 100


class EwelinkAdapter(BaseAdapter):
    """LAN adapter for eWeLink/Sonoff devices."""

    BRAND = "ewelink"

    def __init__(self, apikeys: dict[str, str] | None = None) -> None:
        """
        Args:
            apikeys: Mapping of device_id → apikey.
                     Obtained from cloud pairing or eWeLink app database.
        """
        super().__init__()
        self._apikeys: dict[str, str] = apikeys or {}
        self._zeroconf: AsyncZeroconf | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._http_session: aiohttp.ClientSession | None = None
        self._sequence_counters: dict[str, int] = {}
        self._command_locks: dict[str, asyncio.Lock] = {}

    def set_apikey(self, device_id: str, apikey: str) -> None:
        """Set apikey for a device (can be called after cloud auth)."""
        self._apikeys[device_id] = apikey

    def has_apikey(self, device_id: str) -> bool:
        return bool(self._apikeys.get(device_id))

    def load_device(self, device: DeviceInfo) -> None:
        """Restore an eWeLink inventory record from the persistent registry."""
        if device.brand != self.BRAND:
            raise ValueError(f"Cannot load {device.brand} record into eWeLink adapter")
        self._devices[device.device_id] = device
        self._schedule_poll(device.device_id)

    def _schedule_poll(self, device_id: str) -> None:
        if self._running and not any(
            not task.done() and task.get_name() == f"ewelink-poll:{device_id}"
            for task in self._tasks
        ):
            self._tasks.append(asyncio.create_task(
                self._poll_loop(device_id), name=f"ewelink-poll:{device_id}"
            ))

    async def discover(self, timeout: float | None = None) -> list[DeviceInfo]:
        """Discover eWeLink devices via mDNS."""
        timeout = self.DISCOVERY_TIMEOUT if timeout is None else timeout
        found: dict[str, DeviceInfo] = {}
        pending: set[asyncio.Task[None]] = set()

        def service_task_done(task: asyncio.Task[None]) -> None:
            pending.discard(task)
            if task.cancelled():
                return
            try:
                task.result()
            except Exception:
                logger.debug("eWeLink mDNS service lookup failed", exc_info=True)

        def schedule_service(name: str, service_type: str) -> None:
            task = asyncio.create_task(handle_service(name, service_type))
            pending.add(task)
            task.add_done_callback(service_task_done)

        def on_service_state_change(
            zeroconf: Zeroconf,
            service_type: str,
            name: str,
            state_change: ServiceStateChange,
        ) -> None:
            if state_change != ServiceStateChange.Added:
                return
            schedule_service(name, service_type)

        async def handle_service(name: str, service_type: str) -> None:
            if self._zeroconf is None:
                return
            info = await self._zeroconf.async_get_service_info(service_type, name)
            if info is None:
                return

            props = {
                k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k):
                v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                for k, v in info.properties.items()
            }

            device_id = props.get("id", "")
            if not device_id:
                return

            # Parse TXT record fields
            ip = next(
                (address for address in info.parsed_addresses()
                 if is_lan_unicast_address(address)),
                "",
            )
            if not ip:
                logger.debug("Ignoring eWeLink service %s without a private LAN address", name)
                return
            try:
                raw_uiid = props.get("type", "0") or "0"
                uiid = int(raw_uiid)
            except ValueError:
                logger.debug("Ignoring invalid eWeLink UIID in mDNS record %s", name)
                return
            if not 0 <= uiid <= 65535:
                logger.debug("Ignoring out-of-range eWeLink UIID in mDNS record %s", name)
                return
            # A missing TXT type is unknown, not UIID 1 (a controllable plug).
            props["type"] = str(uiid)

            device = DeviceInfo(
                brand=self.BRAND,
                device_id=device_id,
                ip=ip,
                port=info.port or DEFAULT_PORT,
                device_type=_UIID_MAP.get(uiid, DeviceType.UNKNOWN),
                model=f"UIID_{uiid}",
                name=name.replace(f".{MDNS_SERVICE}", ""),
                raw_metadata=props,
            )

            # If we have encrypted data in TXT, try to decrypt initial state
            apikey = self._apikeys.get(device_id)
            if apikey and props.get("encrypt") and props.get("data1") and props.get("iv"):
                try:
                    decrypted = decrypt_payload(props["data1"], apikey, props["iv"])
                    state_data = json.loads(decrypted)
                    device.raw_metadata["initial_state"] = state_data
                except Exception:
                    logger.debug("Failed to decrypt initial state for %s", device_id)

            # Keep the endpoint and model metadata stable while a local HTTP
            # command is in flight. A concurrent mDNS refresh must not redirect
            # that request or change its device capabilities halfway through.
            lock = self._command_locks.setdefault(device_id, asyncio.Lock())
            async with lock:
                previous = self._devices.get(device_id)
                if previous is not None:
                    previous.ip = device.ip
                    previous.port = device.port
                    # UIID is authoritative even when it maps to UNKNOWN. Keeping
                    # a previous known type here could expose a changed/unsupported
                    # model as a controllable plug in the Matter bridge.
                    previous.device_type = device.device_type
                    previous.model = device.model or previous.model
                    previous.name = device.name or previous.name
                    previous.raw_metadata.update(props)
                    device = previous
                else:
                    self._devices[device_id] = device
            self._schedule_poll(device_id)
            found[device_id] = device
            logger.info("Discovered eWeLink device: %s at %s:%d", device_id, ip, device.port)

        try:
            self._zeroconf = AsyncZeroconf()
            self._browser = AsyncServiceBrowser(
                self._zeroconf.zeroconf, MDNS_SERVICE, handlers=[on_service_state_change]
            )
            await asyncio.sleep(timeout)
        except asyncio.CancelledError:
            for task in pending:
                task.cancel()
            raise
        finally:
            try:
                if self._browser:
                    await self._browser.async_cancel()
            finally:
                self._browser = None
                for task in pending:
                    if not task.done():
                        task.cancel()
                try:
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                finally:
                    if self._zeroconf:
                        try:
                            await self._zeroconf.async_close()
                        finally:
                            self._zeroconf = None

        return list(found.values())

    async def authenticate(self, device: DeviceInfo) -> bool:
        """
        eWeLink LAN auth is implicit — if we have the apikey, we can encrypt.
        Verify by sending an 'info' request.
        """
        apikey = self._apikeys.get(device.device_id)
        if not apikey:
            logger.error("No apikey for device %s", device.device_id)
            return False

        try:
            resp = await self._send_command(device, "info", {})
            authenticated = successful_response(resp)
            device.raw_metadata["lan_authenticated"] = authenticated
            return authenticated
        except Exception:
            logger.exception("Auth check failed for %s", device.device_id)
            device.raw_metadata["lan_authenticated"] = False
            return False

    async def get_state(self, device_id: str) -> DeviceState:
        """Query current device state via HTTP."""
        device = self._devices.get(device_id)
        if not device:
            return DeviceState(online=False)

        try:
            resp = await self._send_command(device, "info", {})
            state = parse_state_response(resp)
            if not state.online:
                return state
            self._states[device_id] = state
            return state

        except Exception:
            logger.exception("Failed to get state for %s", device_id)
            return DeviceState(online=False)

    async def set_state(self, device_id: str, **kwargs: Any) -> bool:
        """Send command to device."""
        device = self._devices.get(device_id)
        if not device:
            return False

        if not kwargs or set(kwargs) - {
            "on", "brightness", "channel", "hue", "saturation", "color_temp", "cover",
        }:
            return False
        # DUALR3 (UIID 126) is a dual relay only in its explicitly reported
        # relay mode. In cover/motor mode, independent relay writes can move a
        # motor in the wrong direction or bypass the device's interlock.
        is_dualr3 = _is_dualr3(device)
        if "cover" in kwargs:
            command = kwargs["cover"]
            direction = command.get("direction") if isinstance(command, dict) else None
            if (not is_dualr3 or set(kwargs) != {"cover"} or not isinstance(command, dict)
                    or set(command) != {"direction"}
                    or not isinstance(direction, str)
                    or direction not in {"open", "close", "stop"}):
                return False
            apikey = self._apikeys.get(device_id)
            if not apikey:
                return False
            motor_turn = {"open": 1, "stop": 0, "close": 2}[direction]
            lock = self._command_locks.setdefault(device_id, asyncio.Lock())
            async with lock:
                # Verify motor mode in the same per-device transaction as the
                # movement command so a stale relay-mode snapshot cannot start it.
                response = await self._send_command_locked(device, "info", {}, apikey)
                state = parse_state_response(response)
                if not state.online:
                    self._states[device_id] = state
                    return False
                params = state.raw.get("params")
                if not isinstance(params, dict) or params.get("workMode") != 2:
                    self._states[device_id] = state
                    return False
                self._states[device_id] = state
                result = await self._send_command_locked(
                    device, "motorTurn", {"motorTurn": motor_turn}, apikey
                )
            return successful_response(result)
        uiid = _ewelink_uiid(device)
        is_color_model = uiid in {22, 59}
        color_fields = set(kwargs) & {"hue", "saturation", "color_temp"}
        if color_fields and (not is_color_model or "channel" in kwargs):
            return False
        if color_fields & {"hue", "saturation"} and not {
            "hue", "saturation",
        }.issubset(kwargs):
            return False
        if color_fields and len(color_fields) > 1 and "color_temp" in color_fields:
            return False
        if is_dualr3 and set(kwargs) != {"on", "channel"}:
            return False
        if "on" in kwargs and not isinstance(kwargs["on"], bool):
            return False
        if "channel" in kwargs and (
            "on" not in kwargs or set(kwargs) != {"on", "channel"}
        ):
            return False
        if "brightness" in kwargs and (
            device.device_type not in {DeviceType.DIMMABLE_LIGHT, DeviceType.COLOR_LIGHT}
            or "channel" in kwargs
        ):
            return False
        if "brightness" in kwargs and (
            not isinstance(kwargs["brightness"], int)
            or isinstance(kwargs["brightness"], bool)
            or not 0 <= kwargs["brightness"] <= 100
        ):
            return False
        if "hue" in kwargs and (
            not isinstance(kwargs["hue"], (int, float))
            or isinstance(kwargs["hue"], bool)
            or not 0 <= kwargs["hue"] <= 360
        ):
            return False
        if "saturation" in kwargs and (
            not isinstance(kwargs["saturation"], (int, float))
            or isinstance(kwargs["saturation"], bool)
            or not 0 <= kwargs["saturation"] <= 100
        ):
            return False
        if "color_temp" in kwargs and (
            uiid != 22
            or not isinstance(kwargs["color_temp"], int)
            or isinstance(kwargs["color_temp"], bool)
            or not 154 <= kwargs["color_temp"] <= 500
        ):
            return False
        if "brightness" in kwargs and kwargs["brightness"] == 0 and color_fields:
            return False
        if (kwargs.get("on") is False
                and (color_fields or kwargs.get("brightness", 0) > 0)):
            return False
        if "on" in kwargs and device.device_type not in {
            DeviceType.ON_OFF_PLUG,
            DeviceType.ON_OFF_LIGHT,
            DeviceType.DIMMABLE_LIGHT,
            DeviceType.COLOR_LIGHT,
            DeviceType.THERMOSTAT,
        }:
            return False
        if is_dualr3:
            # Refresh just before writing; the background poll may be up to
            # POLL_INTERVAL old and the device can switch into motor mode.
            state = await self.get_state(device_id)
            await self.publish_state(device_id, state)
            if not state.online:
                return False
            params = state.raw.get("params")
            if not isinstance(params, dict) or params.get("workMode") != 1:
                return False

        data: dict[str, Any] = {}
        if "brightness" in kwargs:
            if kwargs["brightness"] == 0 and not color_fields:
                if kwargs.get("on") is True:
                    return False
                data = {"switch": "off"}
            elif is_color_model and uiid == 59:
                data.update({"bright": kwargs["brightness"], "mode": 1})
            elif is_color_model and uiid == 22:
                cached = self._states.get(device_id)
                color_temp = kwargs.get("color_temp")
                if color_temp is None and cached is not None:
                    color_temp = cached.color_temp
                kelvin = round(1_000_000 / color_temp) if color_temp else 4250
                channel = str(max(25, min(255, round(25 + kwargs["brightness"] * 2.3))))
                cold, warm = (
                    (channel, "0") if kelvin >= 5000 else
                    (channel, channel) if kelvin >= 3500 else ("0", channel)
                )
                data.update({
                    "channel0": cold, "channel1": warm, "channel2": "0",
                    "channel3": "0", "channel4": "0", "zyx_mode": 1,
                })
            else:
                data["brightness"] = kwargs["brightness"]

        if "color_temp" in kwargs:
            cached = self._states.get(device_id)
            brightness = _color_brightness(kwargs.get("brightness"), cached)
            channel = str(max(25, min(255, round(25 + brightness * 2.3))))
            kelvin = round(1_000_000 / kwargs["color_temp"])
            cold, warm = (
                (channel, "0") if kelvin >= 5000 else
                (channel, channel) if kelvin >= 3500 else ("0", channel)
            )
            data.update({
                "channel0": cold, "channel1": warm, "channel2": "0",
                "channel3": "0", "channel4": "0", "zyx_mode": 1,
            })

        if {"hue", "saturation"}.issubset(kwargs):
            cached = self._states.get(device_id)
            brightness = _color_brightness(kwargs.get("brightness"), cached)
            rgb_brightness = brightness if uiid == 22 else 100
            red, green, blue = _rgb_from_hs(kwargs["hue"], kwargs["saturation"], rgb_brightness)
            if uiid == 22:
                data.update({
                    "channel0": "0", "channel1": "0", "channel2": str(red),
                    "channel3": str(green), "channel4": str(blue), "zyx_mode": 2,
                })
            else:
                data.update({
                    "colorR": red, "colorG": green, "colorB": blue,
                    "light_type": 1, "mode": 1, "bright": brightness,
                })

        if "on" in kwargs and kwargs["on"] is False and color_fields:
            return False

        if "channel" in kwargs and "on" in kwargs:
            # Multi-channel: set specific outlet
            channel = kwargs["channel"]
            if (not isinstance(channel, int) or isinstance(channel, bool)
                    or not 0 <= channel <= 31):
                return False
            state = self._states.get(device_id)
            switches = state.raw.get("switches") if state else None
            if not isinstance(switches, list) or not any(
                isinstance(item, dict) and item.get("outlet") == channel
                for item in switches
            ):
                return False
            data = {
                "switches": [
                    {"switch": "on" if kwargs["on"] else "off", "outlet": channel}
                ]
            }

        if is_color_model and data and "switches" not in data and data.get("switch") != "off":
            apikey = self._apikeys.get(device_id)
            if not apikey:
                return False
            cached = self._states.get(device_id)
            state = cached if cached is not None else await self.get_state(device_id)
            lock = self._command_locks.setdefault(device_id, asyncio.Lock())
            async with lock:
                if state.on is not True:
                    power = await self._send_command_locked(
                        device, "switch", {"switch": "on"}, apikey
                    )
                    if not successful_response(power):
                        return False
                result = await self._send_command_locked(device, "dimmable", data, apikey)
        else:
            if "on" in kwargs:
                data["switch"] = "on" if kwargs["on"] else "off"
            command = "switches" if "switches" in data else "switch"
            result = await self._send_command(device, command, data)

        return successful_response(result)

    async def start(self) -> None:
        if self._running:
            return
        await super().start()
        self._http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.COMMAND_TIMEOUT)
        )
        # Start polling task for each known device.
        for device_id in self._devices:
            self._schedule_poll(device_id)

    async def stop(self) -> None:
        await super().stop()
        if self._browser:
            await self._browser.async_cancel()
            self._browser = None
        if self._zeroconf:
            await self._zeroconf.async_close()
            self._zeroconf = None
        if self._http_session:
            await self._http_session.close()
            self._http_session = None

    # --- Internal ---

    def _next_sequence(self, device_id: str) -> str:
        """Generate a monotonic sequence number (timestamp-based)."""
        seq = max(
            self._sequence_counters.get(device_id, 0) + 1,
            int(time.time() * 1000),
        )
        self._sequence_counters[device_id] = seq
        return str(seq)

    async def _send_command(
        self,
        device: DeviceInfo,
        command: str,
        data: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Send an HTTP POST to the device's zeroconf endpoint.

        Endpoint: POST http://<ip>:8081/zeroconf/<command>

        Payload (encrypted):
            {
                "deviceid": "<id>",
                "data": "<encrypted_data_b64>" | {...},
                "sequence": "<timestamp_ms>",
                "encrypt": true,
                "iv": "<iv_b64>"
            }
        """
        apikey = self._apikeys.get(device.device_id)
        if not apikey:
            logger.error("No apikey for %s", device.device_id)
            return None

        lock = self._command_locks.setdefault(device.device_id, asyncio.Lock())
        async with lock:
            return await self._send_command_locked(device, command, data, apikey)

    async def _send_command_locked(
        self,
        device: DeviceInfo,
        command: str,
        data: dict[str, Any],
        apikey: str,
    ) -> dict[str, Any] | None:
        """Keep commands and their sequence numbers ordered per device."""
        if not self._http_session:
            self._http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.COMMAND_TIMEOUT)
            )

        # Encrypt the data payload
        data_json = json.dumps(data, separators=(",", ":"))
        encrypted_data, iv_b64 = encrypt_payload(data_json, apikey)

        payload = {
            "deviceid": device.device_id,
            "data": encrypted_data,
            "sequence": self._next_sequence(device.device_id),
            "encrypt": True,
            "iv": iv_b64,
        }

        if ":" in device.ip:
            address, separator, scope = device.ip.partition("%")
            scoped_address = f"{address}%25{quote(scope, safe='-._~')}" if separator else address
            host = f"[{scoped_address}]"
        else:
            host = device.ip
        url = f"http://{host}:{device.port}/zeroconf/{command}"
        try:
            async with self._http_session.post(url, json=payload) as resp:
                if resp.status != 200:
                    logger.warning("HTTP %d from %s", resp.status, url)
                    return None
                response_body = bytearray()
                async for chunk in resp.content.iter_chunked(16 * 1024):
                    if len(response_body) + len(chunk) > MAX_RESPONSE_BYTES:
                        logger.warning(
                            "eWeLink response exceeded %d bytes for %s",
                            MAX_RESPONSE_BYTES, device.device_id,
                        )
                        return None
                    response_body.extend(chunk)
                result = json.loads(response_body)
                if not isinstance(result, dict):
                    logger.warning("Unexpected JSON response from %s", url)
                    return None

                # Decrypt response data if encrypted
                if (
                    isinstance(result.get("data"), str)
                    and result.get("encrypt")
                    and result.get("iv")
                ):
                    decrypted = decrypt_payload(result["data"], apikey, result["iv"])
                    result["data"] = json.loads(decrypted)

                return result

        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
            logger.warning("HTTP error for %s: %s", device.device_id, e)
            return None

    async def _poll_loop(self, device_id: str) -> None:
        """Background polling for state changes."""
        while self._running:
            try:
                state = await self.get_state(device_id)
                await self._notify_state_change(device_id, state)
            except Exception:
                logger.debug("Poll error for %s", device_id, exc_info=True)
            await asyncio.sleep(POLL_INTERVAL)
