"""EseeCloud LAN discovery and explicitly configured local HTTP camera streams.

Discovery follows the EseeCloud 4.14.0.4 app's JSON search and only inventories
cameras; it grants no control. Streaming proxies the documented
``/livestream/{channel}`` source only for cameras whose owner has confirmed the
model and local URL format in configuration.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
from yarl import URL

from matter_bridge.core.base_adapter import BaseAdapter, DeviceInfo, DeviceState, DeviceType
from matter_bridge.discovery.network import (
    get_ipv4_broadcast_interfaces,
    is_lan_unicast_address,
)
from matter_bridge.adapters.eseecloud_discovery import (
    DISCOVERY_PORT,
    DISCOVERY_SOURCE_PORT,
    MULTICAST_GROUP,
    EseeCloudDiscoveryReply,
    build_discovery_request,
    parse_discovery_reply,
)
from matter_bridge.adapters.eseecloud_protocol import (
    EseeCloudMediaReader,
    EseeCloudProtocolError,
)

logger = logging.getLogger(__name__)

_DEVICE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)
DISCOVERY_TIMEOUT = 3.0
DISCOVERY_TTL = 300.0
MAX_DISCOVERED = 64
LAN_DISCOVERY_PROTOCOL = "eseecloud_lan_12306"


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
        self._last_seen: dict[str, float] = {}
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
        if device.brand != self.BRAND:
            raise ValueError(f"Cannot load {device.brand} record into EseeCloud adapter")
        if device.device_id in self._targets:
            return
        if (device.raw_metadata.get("discovery_protocol") != LAN_DISCOVERY_PROTOCOL
                or device.device_type is not DeviceType.CAMERA
                or not is_lan_unicast_address(device.ip)):
            raise ValueError("Stored EseeCloud camera has no matching private stream config")
        self._devices[device.device_id] = device

    def has_stream(self, device_id: str) -> bool:
        return device_id in self._targets

    async def discover(self, timeout: float | None = None) -> list[DeviceInfo]:
        timeout = DISCOVERY_TIMEOUT if timeout is None else max(0.0, timeout)
        try:
            replies = await self._lan_search(timeout)
        except OSError:
            logger.debug("EseeCloud LAN search failed", exc_info=True)
            replies = {}
        for source_ip, reply in sorted(replies.items()):
            self._record_reply(source_ip, reply)
        return list(self._devices.values())

    async def _lan_search(self, timeout: float) -> dict[str, EseeCloudDiscoveryReply]:
        """Broadcast the app's discovery request and collect replies by source IP."""
        loop = asyncio.get_running_loop()
        interfaces = [
            (local_ip, broadcast) for local_ip, broadcast in get_ipv4_broadcast_interfaces()
            if is_lan_unicast_address(local_ip)
        ]
        local_ips = {local_ip for local_ip, _ in interfaces}
        replies: dict[str, EseeCloudDiscoveryReply] = {}

        class ReplyProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                source_ip = addr[0]
                if (source_ip in local_ips or not is_lan_unicast_address(source_ip)
                        or len(replies) >= MAX_DISCOVERED):
                    return
                reply = parse_discovery_reply(data)
                if reply is not None:
                    replies[source_ip] = reply

        transports: list[asyncio.DatagramTransport] = []
        try:
            # The app receives replies on multicast 224.2.3.4:12306.
            listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                listener.bind(("0.0.0.0", DISCOVERY_PORT))
                for local_ip in local_ips or {"0.0.0.0"}:
                    try:
                        listener.setsockopt(
                            socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton(local_ip),
                        )
                    except OSError:
                        logger.debug("Could not join %s on %s", MULTICAST_GROUP, local_ip,
                                     exc_info=True)
                transport, _ = await loop.create_datagram_endpoint(
                    ReplyProtocol, sock=listener,
                )
                transports.append(transport)
            except OSError:
                listener.close()
                logger.debug("Could not listen for EseeCloud replies", exc_info=True)

            request = build_discovery_request()
            for local_ip, broadcast in interfaces:
                # The app sends from UDP 57999 on its Wi-Fi address; also accept
                # unicast replies sent back to that socket.
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        ReplyProtocol, local_addr=(local_ip, DISCOVERY_SOURCE_PORT),
                        allow_broadcast=True,
                    )
                except OSError:
                    transport, _ = await loop.create_datagram_endpoint(
                        ReplyProtocol, local_addr=(local_ip, 0), allow_broadcast=True,
                    )
                transports.append(transport)
                for target in {"255.255.255.255", broadcast}:
                    try:
                        transport.sendto(request, (target, DISCOVERY_PORT))
                    except OSError:
                        logger.debug("Could not send EseeCloud search to %s", target,
                                     exc_info=True)
            await asyncio.sleep(timeout)
        finally:
            for transport in transports:
                transport.close()
        return replies

    def _record_reply(self, source_ip: str, reply: EseeCloudDiscoveryReply) -> None:
        """Inventory a discovered camera without storing any reply credentials."""
        metadata = {
            "eseecloud_device_id": reply.device_id,
            "eseecloud_device_type": reply.device_type,
            "eseecloud_version": reply.version,
            "eseecloud_max_channel": reply.max_channel,
        }
        configured = next(
            (device for device_id, device in self._devices.items()
             if device_id in self._targets and device.ip == source_ip),
            None,
        )
        if configured is not None:
            configured.raw_metadata.update(metadata)
            self._last_seen[configured.device_id] = time.monotonic()
            return
        device_id = f"esee-{reply.device_id}"
        device = self._devices.get(device_id)
        if device is None:
            if sum(1 for d in self._devices if d not in self._targets) >= MAX_DISCOVERED:
                return
            device = DeviceInfo(
                brand=self.BRAND,
                device_id=device_id,
                ip=source_ip,
                port=80,
                model="EseeCloud camera",
                name=f"EseeCloud {reply.device_id}",
                device_type=DeviceType.CAMERA,
                raw_metadata={},
            )
            self._devices[device_id] = device
        device.ip = source_ip
        device.raw_metadata.update({**metadata, "discovery_protocol": LAN_DISCOVERY_PROTOCOL})
        self._last_seen[device_id] = time.monotonic()

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
            if device_id not in self._devices:
                return DeviceState(online=False)
            seen = self._last_seen.get(device_id)
            # Discovery-only cameras have no stream; online means "answered recently".
            return DeviceState(
                online=seen is not None and time.monotonic() - seen < DISCOVERY_TTL,
                raw={"stream_protocol": None, "stream_available": False, "tracks": []},
            )
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
