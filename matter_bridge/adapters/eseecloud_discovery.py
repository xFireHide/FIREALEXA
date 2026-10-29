"""EseeCloud LAN device-discovery codec reverse-engineered from the Android app.

The request formats and acceptance rules here are transcribed from a static
JADX analysis of the EseeCloud base APK
(``032b936fddfef856c13ad38274c8f4e9c80e69f34acc5e70a80b74ef7453d431``);
see ``REVERSE_ENGINEERING.md`` for the evidence. The symbols mirror the app's
``MulticastHelper``, ``DeviceProtocolUtil`` and ``NVRProtocolUtil`` classes.

This module only *encodes* the broadcast probes and *parses* the JSON/legacy
responses. It is pure and hardware-independent: no datagram from a target
camera has been captured, so response source-port/timing behaviour and
cross-firmware field presence remain unverified. Nothing here grants control,
credentials or a media stream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# MulticastHelper transport constants (com.juanvision.device.receiver.wifi).
NVR_PORT = 9013
DEFAULT_PORT = 12306
BROADCAST_ADDR = "255.255.255.255"
MULTICAST_ADDR = "224.2.3.4"

# DeviceProtocolUtil.getWifiScanDeviceInfo(int) marks app-originated probes with
# this request ID; the app accepts a common reply only when it echoes this value
# with ``fromApp == false``.
REQUEST_SEARCH_DEVICE = 134489421

# A response larger than this is not a plausible single-device announcement and
# is rejected before any JSON parsing.
MAX_RESPONSE_BYTES = 64 * 1024


def build_common_discovery_request(request_id: int) -> bytes:
    """Build the common (type-100) discovery probe sent to ``DEFAULT_PORT``.

    Matches ``DeviceProtocolUtil.getWifiScanDeviceInfo(int)`` byte-for-byte,
    including the app's fixed ``tokenID`` string and key ordering.
    """
    if not isinstance(request_id, int) or isinstance(request_id, bool):
        raise TypeError("request_id must be an int")
    if not 0 <= request_id <= 0x7FFFFFFF:
        raise ValueError("request_id must fit in a signed 32-bit integer")
    # The app emits compact JSON with these exact keys, order and token.
    return (
        '{"fromApp":true,"requestID":' + str(request_id)
        + ',"tokenID":"1473433878","command":"discovery"}'
    ).encode("ascii")


def build_new_nvr_request(cseq: int) -> bytes:
    """Build the new-NVR (type-100 HDS) probe sent to ``NVR_PORT``.

    Matches ``NVRProtocolUtil.getWifiScanDeviceInfo(int)``: a pseudo-RTSP
    ``SEARCH`` request with a fixed client ID and a 13-byte ``{"Ver":"1.1"}``
    body. The ``CSeq`` increments on each new-NVR scan round.
    """
    if not isinstance(cseq, int) or isinstance(cseq, bool):
        raise TypeError("cseq must be an int")
    if not 0 <= cseq <= 0x7FFFFFFF:
        raise ValueError("cseq must fit in a signed 32-bit integer")
    return (
        "SEARCH * HDS/1.1\r\n"
        f"CSeq:{cseq}\r\n"
        "Client-ID:CeCOlDpmTuzViBQDgbrPgFkfnyyzNabc\r\n"
        "Accept-Type:text/HDP\r\n"
        "Content-Length:13\r\n"
        "X-Search-Type:NVR\r\n"
        '{"Ver":"1.1"}'
    ).encode("ascii")


def build_legacy_nvr_request(serial: str | None = None) -> bytes:
    """Build the legacy (type-101) probe sent to ``NVR_PORT``.

    Matches ``NVRProtocolUtil.getWifiScanDeviceInfo(String)``: ``SEARCHDEV`` for
    a broad scan, or ``SEARCHJA<serial>&`` to probe a known serial.
    """
    if serial is None or serial == "":
        return b"SEARCHDEV"
    if not isinstance(serial, str):
        raise TypeError("serial must be a str or None")
    if not serial.isascii() or any(ord(ch) < 0x20 for ch in serial) or "&" in serial:
        raise ValueError("serial must be printable ASCII without '&'")
    if len(serial) > 64:
        raise ValueError("serial is too long")
    return ("SEARCHJA" + serial + "&").encode("ascii")


@dataclass(slots=True)
class NvrDiscoveryResult:
    """Parsed new-NVR response (``NVRResponseInfo`` Gson model)."""

    esee_id: str
    device_id: str = ""
    device_model: str = ""
    device_type: str = ""
    channel_count: int = 0
    software_version: str = ""
    nonce: str = ""
    ver: str = ""
    http_port: int = 0
    wired: tuple[dict[str, Any], ...] = field(default_factory=tuple)


def _first_json_object(data: bytes) -> dict[str, Any] | None:
    """Decode the JSON object starting at the first ``{``, like the app does.

    ``TaskScanLanDevice.onMultiCastCallback`` slices the payload from its first
    ``{`` before handing it to Gson. Returns ``None`` for anything that is not a
    JSON object, rather than raising.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_RESPONSE_BYTES:
        return None
    start = data.find(b"{")
    if start < 0:
        return None
    try:
        text = data[start:].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    try:
        decoded = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def parse_new_nvr_response(data: bytes) -> NvrDiscoveryResult | None:
    """Parse a new-NVR datagram, accepted only when ``Esee-ID`` is non-empty.

    This is the completion rule from ``handleNewNVRData``: a reply without a
    populated ``Esee-ID`` is ignored.
    """
    obj = _first_json_object(data)
    if obj is None:
        return None
    esee_id = _as_str(obj.get("Esee-ID"))
    if not esee_id:
        return None
    capabilities = obj.get("Capabilities")
    http_port = _as_int(capabilities.get("Http-Port")) if isinstance(capabilities, dict) else 0
    wired_raw = obj.get("Wired")
    wired = tuple(item for item in wired_raw if isinstance(item, dict)) if isinstance(
        wired_raw, list
    ) else ()
    return NvrDiscoveryResult(
        esee_id=esee_id,
        device_id=_as_str(obj.get("Device-ID")),
        device_model=_as_str(obj.get("Device-Model")),
        device_type=_as_str(obj.get("Device-Type")),
        channel_count=_as_int(obj.get("Channel-Cnt")),
        software_version=_as_str(obj.get("Software-Version")),
        nonce=_as_str(obj.get("Nonce")),
        ver=_as_str(obj.get("Ver")),
        http_port=http_port,
        wired=wired,
    )


@dataclass(slots=True)
class CommonDiscoveryResult:
    """Parsed common (type-100) response (``MultiCastResponseInfo`` model)."""

    device_id: str
    uid: str = ""
    version: str = ""
    request_id: int = 0
    device_type: str = ""
    enable_channel: int = 0
    max_channel: int = 0


def parse_common_response(data: bytes) -> CommonDiscoveryResult | None:
    """Parse a common datagram the way ``handleMulticastData`` accepts one.

    The app discards replies unless ``fromApp == false`` and ``requestID``
    echoes :data:`REQUEST_SEARCH_DEVICE`; this rejects the app's own broadcast
    looping back and foreign announcements.
    """
    obj = _first_json_object(data)
    if obj is None:
        return None
    if obj.get("fromApp") is not False:
        return None
    if _as_int(obj.get("requestID")) != REQUEST_SEARCH_DEVICE:
        return None
    device_id = _as_str(obj.get("deviceID"))
    if not device_id:
        return None
    devinfo = obj.get("devinfo")
    if not isinstance(devinfo, dict):
        devinfo = {}
    return CommonDiscoveryResult(
        device_id=device_id,
        uid=_as_str(obj.get("UID")),
        version=_as_str(obj.get("version")),
        request_id=REQUEST_SEARCH_DEVICE,
        device_type=_as_str(devinfo.get("deviceType")),
        enable_channel=_as_int(devinfo.get("enableChannel")),
        max_channel=_as_int(devinfo.get("maxChannel")),
    )
