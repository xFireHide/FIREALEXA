"""ONVIF WS-Discovery inventory for cameras exposing ONVIF on the LAN.

This adapter discovers ONVIF devices and supports authenticated profile reads
and bounded PTZ commands. It does not infer a vendor or turn RTSP into Matter AV.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import logging
import re
import secrets
import socket
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from urllib.parse import quote, unquote, urlsplit

import aiohttp

from matter_bridge.adapters.gwell_protocol import (
    GWELL_SEARCH_PORT,
    GwellSearchReply,
    build_search_request,
    parse_search_reply,
)
from matter_bridge.core.base_adapter import BaseAdapter, DeviceInfo, DeviceState, DeviceType
from matter_bridge.discovery.network import (
    get_ipv4_broadcast_interfaces,
    is_lan_unicast_address,
)

logger = logging.getLogger(__name__)

WS_DISCOVERY_GROUP = "239.255.255.250"
WS_DISCOVERY_PORT = 3702
XM_DISCOVERY_PORT = 8899
XM_DISCOVERY_PROBE = bytes.fromhex(
    "70021c000000000000000000737f759d00000000000001020a00c422"
)
XM_RESPONSE_PREFIX_HINT = b"\x70\x02"
DISCOVERY_TTL = 180.0
POLL_INTERVAL = 30.0
MAX_RESPONSE_BYTES = 64 * 1024
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_PROFILES = 16
MAX_XM_CANDIDATES = 32
SOAP_NAMESPACE = "http://www.w3.org/2003/05/soap-envelope"
WS_ADDRESSING_NAMESPACE = "http://www.w3.org/2005/08/addressing"
DEVICE_NAMESPACE = "http://www.onvif.org/ver10/device/wsdl"
MEDIA_NAMESPACE = "http://www.onvif.org/ver10/media/wsdl"
PTZ_NAMESPACE = "http://www.onvif.org/ver20/ptz/wsdl"
EVENT_NAMESPACE = "http://www.onvif.org/ver10/events/wsdl"
WSN_NAMESPACE = "http://docs.oasis-open.org/wsn/b-2"
WSN_ACTION_NAMESPACE = "http://docs.oasis-open.org/wsn/bw-2"
SCHEMA_NAMESPACE = "http://www.onvif.org/ver10/schema"
WSSE_NAMESPACE = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-secext-1.0.xsd"
)
WSU_NAMESPACE = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-utility-1.0.xsd"
)
PASSWORD_DIGEST_TYPE = f"{WSSE_NAMESPACE}#PasswordDigest"
BASE64_ENCODING_TYPE = f"{WSSE_NAMESPACE}#Base64Binary"
DISCOVERY_ACTION = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
DISCOVERY_TO = "urn:schemas-xmlsoap-org:ws:2005:04:discovery"
PTZ_DIRECTIONS = {
    "up": (0.0, 1.0),
    "down": (0.0, -1.0),
    "left": (-1.0, 0.0),
    "right": (1.0, 0.0),
    "up_left": (-1.0, 1.0),
    "up_right": (1.0, 1.0),
    "down_left": (-1.0, -1.0),
    "down_right": (1.0, -1.0),
}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_text(root: ET.Element, name: str) -> str | None:
    for element in root.iter():
        if _local_name(element.tag) == name and element.text:
            return element.text.strip()
    return None


def _sanitize_xaddr(value: str, source_ip: str) -> str | None:
    """Keep a camera's service path while pinning its host to the packet source."""
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            return None
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if host is None or ipaddress.ip_address(host) != ipaddress.ip_address(source_ip):
            return None
        if not 1 <= port <= 65535 or not parsed.path.startswith("/"):
            return None
        if parsed.query or parsed.fragment:
            return None
    except (ValueError, TypeError):
        return None
    return f"{parsed.scheme}://{source_ip}:{port}{parsed.path}"


def _sanitize_snapshot_uri(value: str, source_ip: str) -> str | None:
    """Keep camera snapshot requests on the discovered host and strip userinfo."""
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if (scheme not in {"http", "https"} or parsed.username or parsed.password
                or parsed.hostname is None
                or ipaddress.ip_address(parsed.hostname) != ipaddress.ip_address(source_ip)
                or not parsed.path.startswith("/") or parsed.fragment
                or len(parsed.query) > 2048):
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
        if not 1 <= port <= 65535:
            return None
    except (ValueError, TypeError):
        return None
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{source_ip}:{port}{parsed.path}{query}"


def _build_probe(message_id: str) -> bytes:
    envelope = ET.Element(
        "{http://www.w3.org/2003/05/soap-envelope}Envelope",
        {
            "xmlns:a": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
            "xmlns:d": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
            "xmlns:dn": "http://www.onvif.org/ver10/network/wsdl",
        },
    )
    header = ET.SubElement(envelope, "{http://www.w3.org/2003/05/soap-envelope}Header")
    ET.SubElement(header, "{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID").text = (
        message_id
    )
    ET.SubElement(header, "{http://schemas.xmlsoap.org/ws/2004/08/addressing}To").text = (
        DISCOVERY_TO
    )
    ET.SubElement(header, "{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action").text = (
        DISCOVERY_ACTION
    )
    body = ET.SubElement(envelope, "{http://www.w3.org/2003/05/soap-envelope}Body")
    probe = ET.SubElement(body, "{http://schemas.xmlsoap.org/ws/2005/04/discovery}Probe")
    ET.SubElement(probe, "{http://schemas.xmlsoap.org/ws/2005/04/discovery}Types").text = (
        "dn:NetworkVideoTransmitter"
    )
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


async def _tcp_port_accepts_connection(host: str, port: int) -> bool:
    """Check one candidate service without keeping its socket open."""
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=0.8)
        return True
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
            except (OSError, asyncio.TimeoutError):
                pass


class OnvifAdapter(BaseAdapter):
    """Discover and control ONVIF cameras using local SOAP services."""

    BRAND = "onvif"
    DISCOVERY_TIMEOUT = 3.0

    def __init__(self, credentials: dict[str, dict[str, str]] | None = None) -> None:
        super().__init__()
        self._credentials = credentials or {}
        self._last_seen: dict[str, float] = {}
        self._sessions: dict[str, aiohttp.ClientSession] = {}
        self._service_cache: dict[str, dict[str, str]] = {}
        self._profiles: dict[str, list[dict[str, str | bool]]] = {}
        self._ptz_locks: dict[str, asyncio.Lock] = {}
        self._digest_nonce_counts: dict[tuple[str, str], int] = {}
        self._digest_locks: dict[str, asyncio.Lock] = {}
        self._event_subscriptions: dict[str, tuple[str, tuple[bytes, ...]]] = {}
        self._motion_states: dict[str, bool] = {}

    def has_credentials(self, device_id: str) -> bool:
        return device_id in self._credentials

    def media_source(self, device_id: str, profile_token: str) -> dict[str, str | bool]:
        """Private IPC source; never serialize this value through the HTTP API."""
        device = self.devices.get(device_id)
        credentials = self._credentials.get(device_id)
        if (device is None or credentials is None
                or device.raw_metadata.get("onvif_authenticated") is not True):
            raise ValueError("Authenticated ONVIF camera is required")
        profile = self._profile_by_selector(device_id, profile_token)
        uri = profile.get("rtsp_uri") if profile else None
        safe = self._sanitize_rtsp_uri(uri, device.ip) if isinstance(uri, str) else None
        if safe is None or not safe.startswith("rtsp://"):
            raise ValueError("A discovered RTSP profile is required")
        parsed = urlsplit(safe)
        user = quote(credentials["username"], safe="")
        password = quote(credentials["password"], safe="")
        return {"uri": f"rtsp://{user}:{password}@{parsed.netloc}{parsed.path}",
                "ip": device.ip, "audio": profile.get("audio") is True}

    def public_profiles(self, device_id: str) -> list[dict[str, str | bool]]:
        """Return stable opaque profile selectors, never ONVIF credentials or URIs."""
        if self.devices.get(device_id) is None:
            return []
        return [{
            "id": hashlib.sha256(str(profile["token"]).encode()).hexdigest()[:24],
            "audio": profile.get("audio") is True,
            "ptz": profile.get("ptz") is True,
            "video_available": (
                isinstance(profile.get("rtsp_uri"), str)
                and urlsplit(str(profile["rtsp_uri"])).scheme == "rtsp"
            ),
        } for profile in self._profiles.get(device_id, [])]

    def _profile_by_selector(self, device_id: str, selector: str) -> dict[str, str | bool] | None:
        return next((profile for profile in self._profiles.get(device_id, [])
                     if profile.get("token") == selector or
                     hashlib.sha256(str(profile.get("token", "")).encode()).hexdigest()[:24]
                     == selector), None)

    def resolve_profile_selector(self, device_id: str, selector: str) -> str | None:
        """Map a public opaque profile selector to its current authenticated profile."""
        profile = self._profile_by_selector(device_id, selector)
        token = profile.get("token") if profile else None
        return token if isinstance(token, str) else None

    def supports_ptz(self, device_id: str) -> bool:
        return (
            "ptz" in self._service_cache.get(device_id, {})
            and any(profile.get("ptz") is True for profile in self._profiles.get(device_id, []))
        )

    def _clear_auth_cache(self, device: DeviceInfo) -> None:
        """Discard cached service/profile data that requires current credentials."""
        device_id = device.device_id
        self._service_cache.pop(device_id, None)
        self._profiles.pop(device_id, None)
        self._event_subscriptions.pop(device_id, None)
        self._motion_states.pop(device_id, None)
        for key in tuple(self._digest_nonce_counts):
            if key[0] == device_id:
                self._digest_nonce_counts.pop(key, None)
        device.raw_metadata.pop("onvif_services", None)
        device.raw_metadata.pop("onvif_profiles", None)
        device.raw_metadata["onvif_authenticated"] = False

    def load_device(self, device: DeviceInfo) -> None:
        if device.brand != self.BRAND:
            raise ValueError(f"Cannot load {device.brand} record into ONVIF adapter")
        if device.device_type is not DeviceType.CAMERA:
            raise ValueError("Stored ONVIF device must have CAMERA type")
        # Service addresses and profile tokens are valid only for the current
        # camera session. Reacquire them after discovery and authentication.
        self._clear_auth_cache(device)
        self._devices[device.device_id] = device

    async def start(self) -> None:
        await super().start()
        for device_id in self._devices:
            self._schedule_poll(device_id)

    async def stop(self) -> None:
        try:
            await super().stop()
            subscriptions = list(self._event_subscriptions.items())
            if subscriptions:
                await asyncio.gather(*(
                    self._unsubscribe_event_subscription(device_id, subscription)
                    for device_id, subscription in subscriptions
                ), return_exceptions=True)
        finally:
            self._event_subscriptions.clear()
            sessions = list(self._sessions.values())
            self._sessions.clear()
            await asyncio.gather(*(session.close() for session in sessions))

    def _schedule_poll(self, device_id: str) -> None:
        task_name = f"onvif-poll:{device_id}"
        if self._running and not any(
            not task.done() and task.get_name() == task_name for task in self._tasks
        ):
            self._tasks.append(asyncio.create_task(
                self._poll_loop(device_id), name=task_name
            ))

    def _schedule_event_poll(self, device_id: str) -> None:
        task_name = f"onvif-events:{device_id}"
        if self._running and not any(
            not task.done() and task.get_name() == task_name for task in self._tasks
        ):
            self._tasks.append(asyncio.create_task(
                self._event_poll_loop(device_id), name=task_name
            ))

    async def _event_poll_loop(self, device_id: str) -> None:
        """Consume standard ONVIF PullPoint events without opening inbound ports."""
        retry_delay = 2.0
        while self._running:
            device = self._devices.get(device_id)
            events_url = self._service_cache.get(device_id, {}).get("events")
            if device is None or events_url is None or not self.has_credentials(device_id):
                await asyncio.sleep(POLL_INTERVAL)
                continue
            try:
                subscription = self._event_subscriptions.get(device_id)
                if subscription is None:
                    subscription = await self._create_event_subscription(
                        device_id, events_url, device.ip
                    )
                    self._event_subscriptions[device_id] = subscription
                subscription_url, reference_parameters = subscription
                response = await self._soap_call(
                    device_id,
                    subscription_url,
                    EVENT_NAMESPACE,
                    "PullMessages",
                    child_builder=self._add_pull_messages_args,
                    action_uri=(
                        f"{EVENT_NAMESPACE}/PullPointSubscription/PullMessagesRequest"
                    ),
                    soap_address=subscription_url,
                    header_elements=reference_parameters,
                    timeout_seconds=15.0,
                )
                retry_delay = 2.0
                motion = self._motion_from_events(response)
                if motion is not None:
                    self._motion_states[device_id] = motion
                    await self.publish_state(device_id, DeviceState(
                        online=True,
                        motion_detected=motion,
                        raw={"onvif_event": "motion", "event_value": motion},
                    ))
                else:
                    # Some cameras return PullMessages immediately instead of
                    # holding the request for its advertised timeout.
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, ET.ParseError):
                self._event_subscriptions.pop(device_id, None)
                logger.debug("ONVIF event poll failed for %s; reconnecting", device_id,
                             exc_info=True)
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60.0)

    async def _create_event_subscription(
        self, device_id: str, events_url: str, source_ip: str
    ) -> tuple[str, tuple[bytes, ...]]:
        response = await self._soap_call(
            device_id,
            events_url,
            EVENT_NAMESPACE,
            "CreatePullPointSubscription",
            action_uri=f"{EVENT_NAMESPACE}/EventPortType/CreatePullPointSubscriptionRequest",
            soap_address=events_url,
        )
        address = None
        reference_parameters: tuple[bytes, ...] = ()
        for reference in response.iter():
            if _local_name(reference.tag) == "SubscriptionReference":
                address = _find_text(reference, "Address")
                for child in reference:
                    if _local_name(child.tag) == "ReferenceParameters":
                        reference_parameters = tuple(
                            ET.tostring(parameter, encoding="utf-8")
                            for parameter in child
                        )
                break
        safe_url = _sanitize_snapshot_uri(address, source_ip) if address else None
        if safe_url is None:
            raise ValueError("Camera returned an unsafe ONVIF event subscription address")
        return safe_url, reference_parameters

    async def _unsubscribe_event_subscription(
        self,
        device_id: str,
        subscription: tuple[str, tuple[bytes, ...]],
    ) -> None:
        subscription_url, reference_parameters = subscription
        try:
            await self._soap_call(
                device_id,
                subscription_url,
                WSN_NAMESPACE,
                "Unsubscribe",
                action_uri=(
                    f"{WSN_ACTION_NAMESPACE}/SubscriptionManager/UnsubscribeRequest"
                ),
                soap_address=subscription_url,
                header_elements=reference_parameters,
                timeout_seconds=3.0,
            )
        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, ET.ParseError):
            logger.debug("ONVIF event unsubscribe failed for %s", device_id,
                         exc_info=True)

    @staticmethod
    def _add_pull_messages_args(request: ET.Element) -> None:
        ET.SubElement(request, f"{{{EVENT_NAMESPACE}}}Timeout").text = "PT5S"
        ET.SubElement(request, f"{{{EVENT_NAMESPACE}}}MessageLimit").text = "16"

    @staticmethod
    def _motion_from_events(root: ET.Element) -> bool | None:
        """Read only explicitly named motion values from ONVIF notifications."""
        result: bool | None = None
        true_values = {"true", "1", "active", "on"}
        false_values = {"false", "0", "inactive", "off"}
        for notification in root.iter():
            if _local_name(notification.tag) != "NotificationMessage":
                continue
            topic = next(
                (element.text or "" for element in notification.iter()
                 if _local_name(element.tag) == "Topic"),
                "",
            ).casefold()
            if "motion" not in topic:
                continue
            for item in notification.iter():
                if _local_name(item.tag) != "SimpleItem":
                    continue
                name = item.attrib.get("Name", "").casefold()
                if name not in {"ismotion", "state", "motion", "motionalarm"}:
                    continue
                value = item.attrib.get("Value", "").strip().casefold()
                if value in true_values:
                    result = True
                elif value in false_values:
                    result = False
        return result

    async def _poll_loop(self, device_id: str) -> None:
        while self._running:
            try:
                await self.publish_state(device_id, await self.get_state(device_id))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("ONVIF state poll failed for %s", device_id, exc_info=True)
            await asyncio.sleep(POLL_INTERVAL)

    async def discover(self, timeout: float | None = None) -> list[DeviceInfo]:
        timeout = self.DISCOVERY_TIMEOUT if timeout is None else max(0.0, timeout)
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(maxsize=256)
        message_id = f"urn:uuid:{uuid.uuid4()}"
        packet = _build_probe(message_id)

        class DiscoveryProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                if len(data) <= MAX_RESPONSE_BYTES and not queue.full():
                    queue.put_nowait((data, addr))

        transports: list[asyncio.DatagramTransport] = []
        gwell_transport: asyncio.DatagramTransport | None = None
        found: dict[str, DeviceInfo] = {}
        xm_candidates: set[str] = set()
        gwell_replies: dict[str, GwellSearchReply] = {}
        interfaces = get_ipv4_broadcast_interfaces()
        local_ips = {local_ip for local_ip, _ in interfaces}

        class GwellProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                source_ip = addr[0]
                if (source_ip in local_ips or not is_lan_unicast_address(source_ip)
                        or len(gwell_replies) >= MAX_XM_CANDIDATES):
                    return
                reply = parse_search_reply(data)
                if reply is not None:
                    gwell_replies[source_ip] = reply

        try:
            # Yoosee 6.46.1 receives search replies on its own bound UDP 8899,
            # not on the request's source port, so listen there as the app does.
            try:
                gwell_transport, _ = await loop.create_datagram_endpoint(
                    GwellProtocol,
                    local_addr=("0.0.0.0", GWELL_SEARCH_PORT),
                    family=socket.AF_INET,
                    allow_broadcast=True,
                    reuse_port=hasattr(socket, "SO_REUSEPORT"),
                )
            except OSError:
                logger.debug("Could not bind Gwell search port %d", GWELL_SEARCH_PORT,
                             exc_info=True)
            else:
                request = build_search_request()
                for target in {"255.255.255.255", *(b for _, b in interfaces)}:
                    try:
                        gwell_transport.sendto(request, (target, GWELL_SEARCH_PORT))
                    except OSError:
                        logger.debug("Could not send Gwell search to %s", target,
                                     exc_info=True)
            for local_ip, broadcast in interfaces:
                if not is_lan_unicast_address(local_ip):
                    continue
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        DiscoveryProtocol,
                        local_addr=(local_ip, 0),
                        family=socket.AF_INET,
                    )
                    udp_socket = transport.get_extra_info("socket")
                    if udp_socket is None:
                        raise OSError("Could not access ONVIF discovery socket")
                    udp_socket.setsockopt(
                        socket.IPPROTO_IP,
                        socket.IP_MULTICAST_IF,
                        socket.inet_aton(local_ip),
                    )
                    udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    transports.append(transport)
                    transport.sendto(packet, (WS_DISCOVERY_GROUP, WS_DISCOVERY_PORT))
                    # Community research documents this probe for some Yoosee/XM
                    # cameras. Its response format is not validated, so only use
                    # the observed header to nominate an IP; TCP service checks and
                    # standard ONVIF authentication below remain authoritative.
                    transport.sendto(XM_DISCOVERY_PROBE, (broadcast, XM_DISCOVERY_PORT))
                except OSError:
                    logger.debug("Could not send ONVIF probe on %s", local_ip, exc_info=True)
                    if "transport" in locals() and transport not in transports:
                        transport.close()
            if not transports:
                raise OSError("No usable IPv4 interface is available for ONVIF discovery")

            deadline = loop.time() + timeout
            while True:
                try:
                    data, (source_ip, source_port) = await asyncio.wait_for(
                        queue.get(), max(0.0, deadline - loop.time())
                    )
                except asyncio.TimeoutError:
                    break
                if (not is_lan_unicast_address(source_ip)
                        or type(source_port) is not int or not 1 <= source_port <= 65535):
                    continue
                if (source_ip not in local_ips and data.startswith(XM_RESPONSE_PREFIX_HINT)):
                    xm_candidates.add(source_ip)
                    continue
                try:
                    upper_data = data.upper()
                    if b"<!DOCTYPE" in upper_data or b"<!ENTITY" in upper_data:
                        continue
                    root = ET.fromstring(data)
                    relates_to = _find_text(root, "RelatesTo")
                    action = _find_text(root, "Action")
                    if (relates_to != message_id or action is None
                            or not action.endswith("/ProbeMatches")):
                        continue
                    endpoint_id = _find_text(root, "Address")
                    xaddrs = _find_text(root, "XAddrs")
                    types = _find_text(root, "Types")
                    if (not endpoint_id or not endpoint_id.startswith("urn:uuid:")
                            or not xaddrs or not types
                            or "NetworkVideoTransmitter" not in types):
                        continue
                    service_url = next(
                        (url for item in xaddrs.split()
                         if (url := _sanitize_xaddr(item, source_ip)) is not None),
                        None,
                    )
                    if service_url is None:
                        continue
                    scopes = _find_text(root, "Scopes") or ""
                    scope_items = [unquote(item) for item in scopes.split()[:64]]
                    scope_values: dict[str, str] = {}
                    for scope in scope_items:
                        for field in ("name", "hardware", "location"):
                            prefix = f"onvif://www.onvif.org/{field}/"
                            if scope.startswith(prefix):
                                scope_values.setdefault(field, scope[len(prefix):])
                    device_id = endpoint_id.removeprefix("urn:uuid:")
                    if not device_id or len(device_id) > 128:
                        continue
                    lock = self._ptz_locks.setdefault(device_id, asyncio.Lock())
                    async with lock:
                        device = self._devices.get(device_id)
                        previous_service_url = None
                        if device is not None:
                            stored_services = device.raw_metadata.get("onvif_services")
                            if isinstance(stored_services, dict):
                                previous_service_url = stored_services.get("device")
                            if not isinstance(previous_service_url, str):
                                try:
                                    previous_service_url = self._service_url(device)
                                except ValueError:
                                    previous_service_url = None
                        if device is None:
                            device = DeviceInfo(
                                brand=self.BRAND,
                                device_id=device_id,
                                ip=source_ip,
                                port=urlsplit(service_url).port or 80,
                                model=scope_values.get("hardware", "ONVIF camera")[:128],
                                name=scope_values.get("name", "")[:128],
                                device_type=DeviceType.CAMERA,
                                raw_metadata={},
                            )
                            self._devices[device_id] = device
                        else:
                            device.ip = source_ip
                            device.port = urlsplit(service_url).port or 80
                            if scope_values.get("hardware"):
                                device.model = scope_values["hardware"][:128]
                            if scope_values.get("name"):
                                device.name = scope_values["name"][:128]
                        if previous_service_url != service_url:
                            self._clear_auth_cache(device)
                        device.raw_metadata.update({
                            "onvif_service_path": urlsplit(service_url).path,
                            "onvif_scheme": urlsplit(service_url).scheme,
                            "discovery_protocol": "onvif_ws_discovery",
                            "scopes": scope_items,
                        })
                        self._last_seen[device_id] = time.monotonic()
                        self._schedule_poll(device_id)
                        found[device_id] = device
                except (ET.ParseError, ValueError, TypeError, OverflowError):
                    logger.debug("Ignoring malformed ONVIF discovery response from %s",
                                 source_ip, exc_info=True)

            for source_ip, reply in sorted(gwell_replies.items())[:MAX_XM_CANDIDATES]:
                device = await self._record_gwell_reply(source_ip, reply, found)
                found[device.device_id] = device

            # XM replies do not have a documented response parser. Restrict these
            # inferred candidates to hosts that also expose the reported ONVIF and
            # RTSP TCP services; they are still not treated as authenticated.
            xm_candidates = set(sorted(xm_candidates - set(gwell_replies))[:MAX_XM_CANDIDATES])
            service_checks = await asyncio.gather(*(
                asyncio.gather(
                    _tcp_port_accepts_connection(source_ip, 5000),
                    _tcp_port_accepts_connection(source_ip, 554),
                )
                for source_ip in sorted(xm_candidates)
            ))
            for source_ip, (onvif_open, rtsp_open) in zip(
                sorted(xm_candidates), service_checks,
            ):
                if (not onvif_open or not rtsp_open
                        or any(device.ip == source_ip for device in found.values())):
                    continue
                device_id = f"yoosee-xm-{source_ip.replace('.', '-')}"
                lock = self._ptz_locks.setdefault(device_id, asyncio.Lock())
                async with lock:
                    device = self._devices.get(device_id)
                    if device is None:
                        device = DeviceInfo(
                            brand=self.BRAND,
                            device_id=device_id,
                            ip=source_ip,
                            port=5000,
                            model="XM-discovered ONVIF camera",
                            name=f"Camera {source_ip}",
                            device_type=DeviceType.CAMERA,
                            raw_metadata={},
                        )
                        self._devices[device_id] = device
                    else:
                        device.ip = source_ip
                        device.port = 5000
                    device.raw_metadata.update({
                        "onvif_scheme": "http",
                        "onvif_service_path": "/onvif/device_service",
                        "discovery_protocol": "xm_udp_8899",
                        "vendor_hint": "Yoosee/XM (unverified)",
                        "rtsp_port_open": True,
                    })
                    self._last_seen[device_id] = time.monotonic()
                    self._schedule_poll(device_id)
                    found[device_id] = device
        except asyncio.CancelledError:
            raise
        finally:
            for transport in transports:
                transport.close()
            if gwell_transport is not None:
                gwell_transport.close()
        return list(found.values())

    async def _record_gwell_reply(
        self, source_ip: str, reply: GwellSearchReply, found: dict[str, DeviceInfo],
    ) -> DeviceInfo:
        """Create or annotate a camera found by the Yoosee/Gwell LAN search.

        The reply identifies a Gwell device but grants no control: the official
        app uses native P2P, not ONVIF. ONVIF is attempted only if the camera
        also accepts TCP 5000 and configured credentials authenticate.
        """
        gwell_metadata = {
            "gwell_device_id": reply.device_id,
            "gwell_type": reply.device_type,
            "gwell_sub_type": reply.sub_type,
            "gwell_custom_id": reply.custom_id,
        }
        existing = next((d for d in found.values() if d.ip == source_ip), None)
        if existing is not None:
            existing.raw_metadata.update(gwell_metadata)
            if reply.mac and not existing.mac:
                existing.mac = reply.mac
            return existing
        onvif_open, rtsp_open = await asyncio.gather(
            _tcp_port_accepts_connection(source_ip, 5000),
            _tcp_port_accepts_connection(source_ip, 554),
        )
        device_id = f"yoosee-{reply.device_id}"
        lock = self._ptz_locks.setdefault(device_id, asyncio.Lock())
        async with lock:
            device = self._devices.get(device_id)
            if device is None:
                device = DeviceInfo(
                    brand=self.BRAND,
                    device_id=device_id,
                    ip=source_ip,
                    port=5000,
                    mac=reply.mac or "",
                    model="Yoosee/Gwell camera",
                    name=f"Yoosee {reply.device_id}",
                    device_type=DeviceType.CAMERA,
                    raw_metadata={},
                )
                self._devices[device_id] = device
            else:
                if device.ip != source_ip:
                    self._clear_auth_cache(device)
                device.ip = source_ip
                device.port = 5000
                if reply.mac:
                    device.mac = reply.mac
            device.raw_metadata.update({
                **gwell_metadata,
                "onvif_scheme": "http",
                "onvif_service_path": "/onvif/device_service",
                "discovery_protocol": "gwell_lan_8899",
                "onvif_port_open": onvif_open,
                "rtsp_port_open": rtsp_open,
            })
            self._last_seen[device_id] = time.monotonic()
            if onvif_open:
                self._schedule_poll(device_id)
        return device

    @staticmethod
    def _service_url(device: DeviceInfo) -> str:
        scheme = device.raw_metadata.get("onvif_scheme", "http")
        path = device.raw_metadata.get("onvif_service_path", "/onvif/device_service")
        if (scheme not in {"http", "https"} or not isinstance(path, str)
                or not path.startswith("/")):
            raise ValueError("Invalid stored ONVIF device service address")
        return f"{scheme}://{device.ip}:{device.port}{path}"

    def _session(self, device_id: str) -> aiohttp.ClientSession:
        session = self._sessions.get(device_id)
        if session is None or session.closed:
            self._sessions[device_id] = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.COMMAND_TIMEOUT),
                connector=aiohttp.TCPConnector(limit=8, limit_per_host=4),
                trust_env=False,
            )
            session = self._sessions[device_id]
        return session

    def _soap_envelope(
        self,
        device_id: str,
        namespace: str,
        operation: str,
        fields: dict[str, str] | None = None,
        *,
        include_security: bool = True,
    ) -> tuple[bytes, str]:
        action = f"{namespace}/{operation}"
        envelope = ET.Element(f"{{{SOAP_NAMESPACE}}}Envelope")
        if include_security:
            username = self._credentials[device_id]["username"]
            password = self._credentials[device_id]["password"]
            header = ET.SubElement(envelope, f"{{{SOAP_NAMESPACE}}}Header")
            security = ET.SubElement(
                header,
                f"{{{WSSE_NAMESPACE}}}Security",
                {f"{{{SOAP_NAMESPACE}}}mustUnderstand": "1"},
            )
            token = ET.SubElement(security, f"{{{WSSE_NAMESPACE}}}UsernameToken")
            ET.SubElement(token, f"{{{WSSE_NAMESPACE}}}Username").text = username
            nonce = secrets.token_bytes(20)
            nonce_b64 = base64.b64encode(nonce).decode("ascii")
            created = (
                datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
            digest = hashlib.sha1(
                nonce + created.encode("utf-8") + password.encode("utf-8"),
                usedforsecurity=False,
            ).digest()
            password_element = ET.SubElement(
                token, f"{{{WSSE_NAMESPACE}}}Password", {"Type": PASSWORD_DIGEST_TYPE}
            )
            password_element.text = base64.b64encode(digest).decode("ascii")
            ET.SubElement(
                token, f"{{{WSSE_NAMESPACE}}}Nonce", {"EncodingType": BASE64_ENCODING_TYPE}
            ).text = nonce_b64
            ET.SubElement(token, f"{{{WSU_NAMESPACE}}}Created").text = created
        body = ET.SubElement(envelope, f"{{{SOAP_NAMESPACE}}}Body")
        request = ET.SubElement(body, f"{{{namespace}}}{operation}")
        for name, value in (fields or {}).items():
            ET.SubElement(request, f"{{{namespace}}}{name}").text = value
        return ET.tostring(envelope, encoding="utf-8", xml_declaration=True), action

    def _digest_authorization(
        self, device_id: str, url: str, challenge: str, *, method: str = "POST"
    ) -> str | None:
        if not challenge.lower().startswith("digest "):
            return None
        parameters = {
            key.lower(): (quoted if quoted is not None else bare)
            .replace('\\"', '"')
            .replace('\\\\', '\\')
            for key, quoted, bare in re.findall(
                r'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^,\s]+))',
                challenge[7:],
            )
        }
        realm = parameters.get("realm")
        nonce = parameters.get("nonce")
        algorithm = parameters.get("algorithm", "MD5").upper()
        if not realm or not nonce or algorithm not in {
            "MD5", "MD5-SESS", "SHA-256", "SHA-256-SESS",
        }:
            return None
        username = self._credentials[device_id]["username"]
        password = self._credentials[device_id]["password"]
        digest_name = "sha256" if algorithm.startswith("SHA-256") else "md5"
        qop_options = [item.strip().lower() for item in parameters.get("qop", "").split(",")]
        qop = "auth" if "auth" in qop_options else ""
        if qop_options and not qop:
            return None
        cnonce = secrets.token_hex(16)
        count_key = (device_id, nonce)
        nonce_count = self._digest_nonce_counts.get(count_key, 0) + 1
        self._digest_nonce_counts[count_key] = nonce_count
        if len(self._digest_nonce_counts) > 128:
            oldest_nonce = next(iter(self._digest_nonce_counts))
            self._digest_nonce_counts.pop(oldest_nonce, None)
        nc = f"{nonce_count:08x}"

        def digest(value: str) -> str:
            return hashlib.new(
                digest_name, value.encode("utf-8"), usedforsecurity=False
            ).hexdigest()

        ha1 = digest(f"{username}:{realm}:{password}")
        if algorithm.endswith("-SESS"):
            ha1 = digest(f"{ha1}:{nonce}:{cnonce}")
        parsed_url = urlsplit(url)
        uri = parsed_url.path or "/"
        if parsed_url.query:
            uri += f"?{parsed_url.query}"
        ha2 = digest(f"{method.upper()}:{uri}")
        if qop:
            response_hash = digest(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        else:
            response_hash = digest(f"{ha1}:{nonce}:{ha2}")

        def quoted_value(value: str) -> str:
            return value.replace("\\", "\\\\").replace('"', '\\"')

        parts = [
            f'username="{quoted_value(username)}"',
            f'realm="{quoted_value(realm)}"',
            f'nonce="{quoted_value(nonce)}"',
            f'uri="{quoted_value(uri)}"',
            f'response="{response_hash}"',
            f"algorithm={algorithm}",
        ]
        if qop:
            parts.extend((f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'))
        elif algorithm.endswith("-SESS"):
            parts.append(f'cnonce="{cnonce}"')
        if parameters.get("opaque"):
            parts.append(f'opaque="{quoted_value(parameters["opaque"])}"')
        return "Digest " + ", ".join(parts)

    async def _digest_authorization_locked(
        self, device_id: str, url: str, challenge: str, *, method: str = "POST"
    ) -> str | None:
        """Allocate nonce counts atomically for concurrent requests to one camera."""
        lock = self._digest_locks.setdefault(device_id, asyncio.Lock())
        async with lock:
            return self._digest_authorization(
                device_id, url, challenge, method=method
            )

    async def _soap_call(
        self,
        device_id: str,
        url: str,
        namespace: str,
        operation: str,
        fields: dict[str, str] | None = None,
        *,
        child_builder: Callable[[ET.Element], None] | None = None,
        action_uri: str | None = None,
        soap_address: str | None = None,
        header_elements: tuple[bytes, ...] = (),
        timeout_seconds: float | None = None,
    ) -> ET.Element:
        action = action_uri or f"{namespace}/{operation}"

        def build_payload(include_security: bool) -> bytes:
            envelope_bytes, _ = self._soap_envelope(
                device_id, namespace, operation, fields, include_security=include_security
            )
            if child_builder is None and soap_address is None and not header_elements:
                return envelope_bytes
            root = ET.fromstring(envelope_bytes)
            header = next(
                (element for element in root if _local_name(element.tag) == "Header"),
                None,
            )
            if soap_address is not None or header_elements:
                if header is None:
                    header = ET.Element(f"{{{SOAP_NAMESPACE}}}Header")
                    body_index = next(
                        index for index, element in enumerate(root)
                        if _local_name(element.tag) == "Body"
                    )
                    root.insert(body_index, header)
                if soap_address is not None:
                    addressing_attributes = {
                        f"{{{SOAP_NAMESPACE}}}mustUnderstand": "1"
                    }
                    ET.SubElement(
                        header,
                        f"{{{WS_ADDRESSING_NAMESPACE}}}Action",
                        addressing_attributes,
                    ).text = action
                    ET.SubElement(
                        header, f"{{{WS_ADDRESSING_NAMESPACE}}}MessageID"
                    ).text = f"urn:uuid:{uuid.uuid4()}"
                    ET.SubElement(
                        header,
                        f"{{{WS_ADDRESSING_NAMESPACE}}}To",
                        addressing_attributes,
                    ).text = soap_address
                for element_bytes in header_elements:
                    header.append(ET.fromstring(element_bytes))
            if child_builder is not None:
                body = next(element for element in root if _local_name(element.tag) == "Body")
                request = next(iter(body))
                child_builder(request)
            return ET.tostring(root, encoding="utf-8", xml_declaration=True)

        headers = {
            "Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"',
            "SOAPAction": f'"{action}"',
        }
        session = self._session(device_id)
        timeout = (
            aiohttp.ClientTimeout(total=timeout_seconds)
            if timeout_seconds is not None else None
        )
        payload = bytearray()
        async with session.post(url, data=build_payload(True), headers=headers,
                                allow_redirects=False, timeout=timeout) as response:
            async for chunk in response.content.iter_chunked(8192):
                if len(payload) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError("ONVIF SOAP response exceeded the size limit")
                payload.extend(chunk)
            status = response.status
            challenge = next(
                (value for value in response.headers.getall("WWW-Authenticate", [])
                 if value.lower().startswith("digest ")),
                "",
            )
        if status == 401:
            authorization = await self._digest_authorization_locked(
                device_id, url, challenge
            )
            if authorization is not None:
                async with session.post(
                    url,
                    data=build_payload(False),
                    headers={**headers, "Authorization": authorization},
                    allow_redirects=False,
                    timeout=timeout,
                ) as response:
                    payload = bytearray()
                    async for chunk in response.content.iter_chunked(8192):
                        if len(payload) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise ValueError("ONVIF SOAP response exceeded the size limit")
                        payload.extend(chunk)
                    status = response.status
        if status != 200:
            raise ValueError(f"ONVIF {operation} returned HTTP {status}")
        payload_bytes = bytes(payload)
        if b"<!DOCTYPE" in payload_bytes.upper() or b"<!ENTITY" in payload_bytes.upper():
            raise ValueError("ONVIF SOAP response contains a forbidden XML declaration")
        root = ET.fromstring(payload_bytes)
        if any(_local_name(element.tag) == "Fault" for element in root.iter()):
            raise ValueError(f"ONVIF {operation} returned a SOAP fault")
        return root

    @staticmethod
    def _service_xaddr(root: ET.Element, service_name: str, device_ip: str) -> str | None:
        for capabilities in root.iter():
            if _local_name(capabilities.tag) != "Capabilities":
                continue
            for service in capabilities:
                if _local_name(service.tag) != service_name:
                    continue
                xaddr = _find_text(service, "XAddr")
                if xaddr:
                    return _sanitize_xaddr(xaddr, device_ip)
        return None

    @staticmethod
    def _profile_tokens(root: ET.Element) -> list[dict[str, str | bool]]:
        profiles: list[dict[str, str | bool]] = []
        for element in root.iter():
            if _local_name(element.tag) != "Profiles":
                continue
            token = element.attrib.get("token", "")
            if not token or len(token) > 256:
                continue
            has_ptz = any(_local_name(child.tag) == "PTZConfiguration" for child in element)
            has_audio = any(_local_name(child.tag) == "AudioEncoderConfiguration" for child in element)
            profiles.append({"token": token, "ptz": has_ptz, "audio": has_audio})
            if len(profiles) >= MAX_PROFILES:
                break
        return profiles

    @staticmethod
    def _sanitize_rtsp_uri(uri: str, device_ip: str) -> str | None:
        try:
            parsed = urlsplit(uri)
            if (parsed.scheme.lower() not in {"rtsp", "rtsps"}
                    or parsed.username or parsed.password or parsed.hostname is None
                    or ipaddress.ip_address(parsed.hostname) != ipaddress.ip_address(device_ip)
                    or not parsed.path.startswith("/") or parsed.fragment):
                return None
            port = parsed.port or (322 if parsed.scheme.lower() == "rtsps" else 554)
            if not 1 <= port <= 65535:
                return None
        except (ValueError, TypeError):
            return None
        return f"{parsed.scheme.lower()}://{device_ip}:{port}{parsed.path}"

    async def authenticate(self, device: DeviceInfo) -> bool:
        """Authenticate with WS-Security and cache local services and media profiles."""
        if device.brand != self.BRAND:
            return False
        lock = self._ptz_locks.setdefault(device.device_id, asyncio.Lock())
        async with lock:
            return await self._authenticate_locked(device)

    async def _authenticate_locked(self, device: DeviceInfo) -> bool:
        self._clear_auth_cache(device)
        if not self.has_credentials(device.device_id):
            return False
        try:
            device_url = self._service_url(device)
            root = await self._soap_call(
                device.device_id, device_url, DEVICE_NAMESPACE, "GetCapabilities",
                {"Category": "All"},
            )
            services = {"device": device_url}
            media_url = self._service_xaddr(root, "Media", device.ip)
            ptz_url = self._service_xaddr(root, "PTZ", device.ip)
            events_url = self._service_xaddr(root, "Events", device.ip)
            if media_url:
                services["media"] = media_url
            if ptz_url:
                services["ptz"] = ptz_url
            if events_url:
                services["events"] = events_url

            profiles: list[dict[str, str | bool]] = []
            if media_url:
                profiles_root = await self._soap_call(
                    device.device_id, media_url, MEDIA_NAMESPACE, "GetProfiles"
                )
                profiles = self._profile_tokens(profiles_root)
                for profile in profiles:
                    try:
                        stream_root = await self._soap_call(
                            device.device_id,
                            media_url,
                            MEDIA_NAMESPACE,
                            "GetStreamUri",
                            child_builder=lambda request, profile=profile:
                                self._add_stream_uri_args(request, str(profile["token"])),
                        )
                        uri = _find_text(stream_root, "Uri")
                        safe_uri = self._sanitize_rtsp_uri(uri, device.ip) if uri else None
                        if safe_uri:
                            profile["rtsp_uri"] = safe_uri
                    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, ET.ParseError):
                        logger.debug("ONVIF stream URI unavailable for %s", device.device_id,
                                     exc_info=True)
            self._service_cache[device.device_id] = services
            self._profiles[device.device_id] = profiles
            device.raw_metadata["onvif_services"] = services
            device.raw_metadata["onvif_profiles"] = profiles
            device.raw_metadata["onvif_authenticated"] = True
            if events_url:
                self._schedule_event_poll(device.device_id)
            return True
        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, ET.ParseError) as exc:
            self._clear_auth_cache(device)
            logger.warning("ONVIF authentication failed for %s: %s", device.device_id, exc)
            return False

    @staticmethod
    def _add_stream_uri_args(request: ET.Element, profile_token: str) -> None:
        stream_setup = ET.SubElement(request, f"{{{MEDIA_NAMESPACE}}}StreamSetup")
        ET.SubElement(stream_setup, f"{{{SCHEMA_NAMESPACE}}}Stream").text = "RTP-Unicast"
        transport = ET.SubElement(stream_setup, f"{{{SCHEMA_NAMESPACE}}}Transport")
        ET.SubElement(transport, f"{{{SCHEMA_NAMESPACE}}}Protocol").text = "RTSP"
        ET.SubElement(request, f"{{{MEDIA_NAMESPACE}}}ProfileToken").text = profile_token

    @staticmethod
    def _add_snapshot_uri_args(request: ET.Element, profile_token: str) -> None:
        ET.SubElement(request, f"{{{MEDIA_NAMESPACE}}}ProfileToken").text = profile_token

    async def get_snapshot(self, device_id: str, profile_token: str) -> bytes:
        """Fetch an authenticated ONVIF JPEG snapshot for a discovered profile."""
        lock = self._ptz_locks.setdefault(device_id, asyncio.Lock())
        async with lock:
            return await self._get_snapshot_locked(device_id, profile_token)

    async def _get_snapshot_locked(self, device_id: str, profile_token: str) -> bytes:
        """Read a snapshot while discovery/authentication cannot replace its cache."""
        device = self._devices.get(device_id)
        services = self._service_cache.get(device_id)
        profiles = self._profiles.get(device_id, [])
        if (device is None or not self.has_credentials(device_id)
                or device.raw_metadata.get("onvif_authenticated") is not True
                or not services or "media" not in services
                or not any(item.get("token") == profile_token for item in profiles)):
            raise ValueError("Camera credentials and a discovered media profile are required")

        root = await self._soap_call(
            device_id,
            services["media"],
            MEDIA_NAMESPACE,
            "GetSnapshotUri",
            child_builder=lambda request: self._add_snapshot_uri_args(request, profile_token),
        )
        snapshot_uri = _find_text(root, "Uri")
        safe_uri = _sanitize_snapshot_uri(snapshot_uri, device.ip) if snapshot_uri else None
        if safe_uri is None:
            raise ValueError("Camera returned an unsafe or invalid snapshot URI")

        session = self._session(device_id)
        headers = {"Accept": "image/jpeg"}
        payload = bytearray()
        async with session.get(safe_uri, headers=headers, allow_redirects=False) as response:
            challenge = next(
                (value for value in response.headers.getall("WWW-Authenticate", [])
                 if value.lower().startswith("digest ")),
                "",
            )
            status = response.status
            if status != 401:
                async for chunk in response.content.iter_chunked(16 * 1024):
                    if len(payload) + len(chunk) > MAX_SNAPSHOT_BYTES:
                        raise ValueError("ONVIF snapshot exceeded the size limit")
                    payload.extend(chunk)
        if status == 401:
            authorization = await self._digest_authorization_locked(
                device_id, safe_uri, challenge, method="GET"
            )
            if authorization is None:
                raise ValueError("Camera snapshot requires unsupported HTTP authentication")
            async with session.get(
                safe_uri,
                headers={**headers, "Authorization": authorization},
                allow_redirects=False,
            ) as response:
                if response.status != 200:
                    raise ValueError(f"ONVIF snapshot returned HTTP {response.status}")
                async for chunk in response.content.iter_chunked(16 * 1024):
                    if len(payload) + len(chunk) > MAX_SNAPSHOT_BYTES:
                        raise ValueError("ONVIF snapshot exceeded the size limit")
                    payload.extend(chunk)
        elif status != 200:
            raise ValueError(f"ONVIF snapshot returned HTTP {status}")

        image = bytes(payload)
        if len(image) < 4 or not image.startswith(b"\xff\xd8") or not image.endswith(b"\xff\xd9"):
            raise ValueError("Camera snapshot response is not a complete JPEG image")
        return image

    async def _send_ptz_stop(self, device_id: str, profile_token: str) -> None:
        services = self._service_cache[device_id]
        await self._soap_call(
            device_id,
            services["ptz"],
            PTZ_NAMESPACE,
            "Stop",
            child_builder=lambda request: self._add_stop_args(request, profile_token),
        )

    @staticmethod
    def _add_stop_args(request: ET.Element, profile_token: str) -> None:
        ET.SubElement(request, f"{{{PTZ_NAMESPACE}}}ProfileToken").text = profile_token
        ET.SubElement(request, f"{{{PTZ_NAMESPACE}}}PanTilt").text = "true"
        ET.SubElement(request, f"{{{PTZ_NAMESPACE}}}Zoom").text = "true"

    async def set_state(self, device_id: str, **kwargs: object) -> bool:
        if (set(kwargs) != {"ptz"} or device_id not in self._service_cache
                or not self.has_credentials(device_id)):
            return False
        request = kwargs["ptz"]
        if not isinstance(request, dict) or set(request) - {"direction", "duration_ms", "speed"}:
            return False
        direction = request.get("direction")
        if direction == "stop":
            direction_velocity = None
        elif isinstance(direction, str):
            direction_velocity = PTZ_DIRECTIONS.get(direction)
        else:
            return False
        if direction_velocity is None and direction != "stop":
            return False
        duration = request.get("duration_ms", 500)
        speed = request.get("speed", 0.5)
        if (not isinstance(duration, int) or isinstance(duration, bool)
                or not 100 <= duration <= 5000):
            return False
        if (not isinstance(speed, (int, float)) or isinstance(speed, bool)
                or not 0.05 <= speed <= 1.0):
            return False
        profiles = self._profiles.get(device_id, [])
        profile = next((item for item in profiles if item.get("ptz") is True), None)
        services = self._service_cache[device_id]
        if "ptz" not in services or profile is None:
            return False
        profile_token = str(profile["token"])
        lock = self._ptz_locks.setdefault(device_id, asyncio.Lock())
        async with lock:
            # Authentication or rediscovery may have replaced the caches while
            # this command was waiting for the per-camera lock.
            profiles = self._profiles.get(device_id, [])
            profile = next((item for item in profiles if item.get("ptz") is True), None)
            services = self._service_cache.get(device_id, {})
            if not self.has_credentials(device_id) or "ptz" not in services or profile is None:
                return False
            profile_token = str(profile["token"])
            try:
                if direction == "stop":
                    await self._send_ptz_stop(device_id, profile_token)
                    return True
                pan, tilt = direction_velocity
                timeout_seconds = duration / 1000
                await self._soap_call(
                    device_id,
                    services["ptz"],
                    PTZ_NAMESPACE,
                    "ContinuousMove",
                    child_builder=lambda command: self._add_continuous_move_args(
                        command, profile_token, pan * float(speed), tilt * float(speed),
                        timeout_seconds,
                    ),
                )
                stop_succeeded = True
                try:
                    await asyncio.sleep(timeout_seconds)
                finally:
                    # A client disconnect/cancellation must not leave a camera
                    # moving indefinitely. Shield the stop request from the
                    # cancellation that interrupted the bounded move.
                    stop_task = asyncio.create_task(
                        asyncio.wait_for(
                            self._send_ptz_stop(device_id, profile_token),
                            timeout=self.COMMAND_TIMEOUT + 1.0,
                        )
                    )
                    try:
                        await asyncio.shield(stop_task)
                    except asyncio.CancelledError:
                        # Preserve the caller's cancellation after making a
                        # best effort to complete the safety stop.
                        try:
                            await asyncio.shield(stop_task)
                        except (aiohttp.ClientError, asyncio.TimeoutError,
                                ValueError, ET.ParseError):
                            logger.warning(
                                "ONVIF PTZ safety stop failed for %s", device_id,
                                exc_info=True,
                            )
                        raise
                    except (aiohttp.ClientError, asyncio.TimeoutError,
                            ValueError, ET.ParseError):
                        stop_succeeded = False
                        logger.warning(
                            "ONVIF PTZ safety stop failed for %s", device_id,
                            exc_info=True,
                        )
                if not stop_succeeded:
                    return False
                return True
            except asyncio.CancelledError:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, ET.ParseError):
                logger.warning("ONVIF PTZ command failed for %s", device_id, exc_info=True)
                return False

    @staticmethod
    def _add_continuous_move_args(
        request: ET.Element,
        profile_token: str,
        pan: float,
        tilt: float,
        timeout_seconds: float,
    ) -> None:
        ET.SubElement(request, f"{{{PTZ_NAMESPACE}}}ProfileToken").text = profile_token
        velocity = ET.SubElement(request, f"{{{PTZ_NAMESPACE}}}Velocity")
        ET.SubElement(
            velocity,
            f"{{{SCHEMA_NAMESPACE}}}PanTilt",
            {"x": f"{pan:.3f}", "y": f"{tilt:.3f}"},
        )
        ET.SubElement(velocity, f"{{{SCHEMA_NAMESPACE}}}Zoom", {"x": "0"})
        ET.SubElement(request, f"{{{PTZ_NAMESPACE}}}Timeout").text = (
            f"PT{timeout_seconds:.3f}S"
        )

    async def get_state(self, device_id: str) -> DeviceState:
        device = self._devices.get(device_id)
        last_seen = self._last_seen.get(device_id)
        if device is None or last_seen is None:
            return DeviceState(online=False)
        return DeviceState(
            online=time.monotonic() - last_seen <= DISCOVERY_TTL,
            motion_detected=self._motion_states.get(device_id),
        )

