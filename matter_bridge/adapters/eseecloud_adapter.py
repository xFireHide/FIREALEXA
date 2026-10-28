"""Explicitly configured EseeCloud-compatible local HTTP camera streams.

This is not a vendor-wide discovery or control implementation. It only proxies
the documented ``/livestream/{channel}`` source for cameras whose owner has
confirmed the model and local URL format.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
from yarl import URL

from matter_bridge.core.base_adapter import BaseAdapter, DeviceInfo, DeviceState, DeviceType
from matter_bridge.discovery.network import is_lan_unicast_address
from matter_bridge.adapters.eseecloud_protocol import (
    EseeCloudMediaReader,
    EseeCloudProtocolError,
)

logger = logging.getLogger(__name__)

_DEVICE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)


class EseeCloudStreamBusyError(RuntimeError):
    """Raised when the camera already has the allowed number of viewers."""


class EseeCloudAdapter(BaseAdapter):
    """Proxy manually configured EseeCloud-compatible camera streams."""

    BRAND = "eseecloud"

    def __init__(self, streams: dict[str, dict[str, Any]] | None = None) -> None:
        super().__init__()
        self._targets: dict[str, tuple[URL, aiohttp.BasicAuth | None]] = {}
        self._online: dict[str, bool] = {}
        self._tracks: dict[str, tuple[dict[str, int | str], ...]] = {}
        self._stream_limits: dict[str, asyncio.Semaphore] = {}
        self._session: aiohttp.ClientSession | None = None
        for device_id, settings in (streams or {}).items():
            if not isinstance(device_id, str) or _DEVICE_ID.fullmatch(device_id) is None:
                raise ValueError(
                    "EseeCloud stream IDs must use 1-64 ASCII letters, digits, '_' or '-'"
                )
            if not isinstance(settings, dict) or set(settings) - {
                "ip", "port", "channel", "username", "password", "name",
            }:
                raise ValueError(f"eseecloud_streams[{device_id!r}] has unsupported settings")
            ip = settings.get("ip")
            if not isinstance(ip, str) or not is_lan_unicast_address(ip):
                raise ValueError(f"eseecloud_streams[{device_id!r}].ip must be a private LAN IP")
            try:
                address = ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ValueError(f"eseecloud_streams[{device_id!r}].ip is invalid") from exc
            if address.version != 4:
                raise ValueError("EseeCloud HTTP stream targets must use IPv4 addresses")
            port = settings.get("port", 80)
            channel = settings.get("channel", 12)
            if (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
                raise ValueError(f"eseecloud_streams[{device_id!r}].port must be 1-65535")
            if (not isinstance(channel, int) or isinstance(channel, bool)
                    or not 0 <= channel <= 255):
                raise ValueError(f"eseecloud_streams[{device_id!r}].channel must be 0-255")
            username = settings.get("username", "")
            password = settings.get("password", "")
            name = settings.get("name", device_id)
            for field, value in (("username", username), ("password", password)):
                if (not isinstance(value, str) or len(value) > 256
                        or any(ord(character) < 0x20 for character in value)):
                    raise ValueError(f"eseecloud_streams[{device_id!r}].{field} is invalid")
            if ":" in username:
                raise ValueError(
                    f"eseecloud_streams[{device_id!r}].username cannot contain ':'"
                )
            if not isinstance(name, str) or not name or len(name) > 128:
                raise ValueError(f"eseecloud_streams[{device_id!r}].name must be 1-128 chars")

            info = DeviceInfo(
                brand=self.BRAND,
                device_id=device_id,
                ip=ip,
                port=port,
                model="EseeCloud-compatible HTTP camera",
                name=name,
                device_type=DeviceType.CAMERA,
                raw_metadata={
                    "discovery_protocol": "eseecloud_http_stream_config",
                    "stream_channel": channel,
                },
            )
            self._devices[device_id] = info
            self._targets[device_id] = (
                URL.build(scheme="http", host=ip, port=port, path=f"/livestream/{channel}"),
                aiohttp.BasicAuth(username, password) if username or password else None,
            )
            self._online[device_id] = False
            self._stream_limits[device_id] = asyncio.Semaphore(2)

    async def start(self) -> None:
        await super().start()
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(
                total=None, connect=3.0, sock_read=30.0,
            ))

    async def stop(self) -> None:
        try:
            await super().stop()
        finally:
            session, self._session = self._session, None
            if session is not None and not session.closed:
                await session.close()

    def load_device(self, device: DeviceInfo) -> None:
        if device.brand != self.BRAND or device.device_id not in self._targets:
            raise ValueError("Stored EseeCloud camera has no matching private stream config")

    async def discover(self, timeout: float | None = None) -> list[DeviceInfo]:
        del timeout
        return list(self._devices.values())

    async def authenticate(self, device: DeviceInfo) -> bool:
        target = self._targets.get(device.device_id)
        if target is None:
            return False
        url, auth = target
        session = self._get_session()
        limit = self._stream_limits[device.device_id]
        try:
            await asyncio.wait_for(limit.acquire(), timeout=2.0)
        except asyncio.TimeoutError:
            # Active viewers already occupy the camera's connection budget.
            return self._online.get(device.device_id, False)
        response: aiohttp.ClientResponse | None = None
        try:
            response = await session.get(url, auth=auth, allow_redirects=False)
            if response.status != 200:
                self._tracks.pop(device.device_id, None)
                self._online[device.device_id] = False
                return False
            media = EseeCloudMediaReader(response.content)
            await asyncio.wait_for(media.read_preamble(), timeout=5.0)
            self._tracks[device.device_id] = media.media_tracks
            online = True
        except (aiohttp.ClientError, asyncio.TimeoutError, EseeCloudProtocolError):
            self._tracks.pop(device.device_id, None)
            self._online[device.device_id] = False
            logger.debug("EseeCloud stream probe failed for %s", device.device_id, exc_info=True)
            return False
        finally:
            if response is not None:
                response.close()
            limit.release()
        self._online[device.device_id] = online
        return online

    async def get_state(self, device_id: str) -> DeviceState:
        if device_id not in self._targets:
            return DeviceState(online=False)
        return DeviceState(
            online=self._online.get(device_id, False),
            raw={
                "stream_protocol": "eseecloud_http_rtp",
                "stream_available": self._online.get(device_id, False),
                "tracks": list(self._tracks.get(device_id, ())),
            },
        )

    def is_online(self, device_id: str) -> bool:
        return self._online.get(device_id, False)

    async def mark_offline(self, device_id: str) -> None:
        if device_id in self._online:
            self._online[device_id] = False
            self._tracks.pop(device_id, None)
            await self.publish_state(device_id, await self.get_state(device_id))

    async def mark_stream_valid(
        self, device_id: str, tracks: tuple[dict[str, int | str], ...]
    ) -> None:
        if device_id in self._online:
            self._online[device_id] = True
            self._tracks[device_id] = tracks
            await self.publish_state(device_id, await self.get_state(device_id))

    async def set_state(self, device_id: str, **kwargs: Any) -> bool:
        del device_id, kwargs
        return False

    @asynccontextmanager
    async def stream(self, device_id: str) -> AsyncIterator[aiohttp.ClientResponse]:
        """Yield a raw camera response with bounded concurrent clients."""
        target = self._targets.get(device_id)
        limit = self._stream_limits.get(device_id)
        if target is None or limit is None:
            raise KeyError(device_id)
        try:
            await asyncio.wait_for(limit.acquire(), timeout=2.0)
        except asyncio.TimeoutError as exc:
            raise EseeCloudStreamBusyError(
                "Too many local viewers for this camera"
            ) from exc

        url, auth = target
        response: aiohttp.ClientResponse | None = None
        try:
            response = await self._get_session().get(url, auth=auth, allow_redirects=False)
            if response.status != 200:
                self._online[device_id] = False
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message="EseeCloud camera rejected the local stream request",
                )
            self._online[device_id] = True
            yield response
        except (aiohttp.ClientError, asyncio.TimeoutError):
            self._online[device_id] = False
            raise
        finally:
            if response is not None:
                response.close()
            limit.release()

    def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            raise RuntimeError("EseeCloud adapter is not running")
        return self._session
