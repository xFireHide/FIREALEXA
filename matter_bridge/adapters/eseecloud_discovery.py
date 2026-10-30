"""EseeCloud/JuanVision LAN camera discovery datagrams.

Layout from EseeCloud 4.14.0.4 (``TaskScanLanDevice``, ``MulticastHelper`` and
``DeviceProtocolUtil.getWifiScanDeviceInfo``): the app broadcasts a JSON request
to UDP 12306 from source port 57999 and receives replies on multicast group
224.2.3.4:12306.

Replies also carry ``UID``, ``devKey`` and ``devinfo.ulinkToken``. The app
derives the device password from ``UID`` and ``devKey``, so the parser never
returns them and nothing here stores them.

NVR recorders answer a separate pseudo-RTSP ``SEARCH * HDS/1.1`` probe on UDP
9013 (``NVRProtocolUtil.getWifiScanDeviceInfo(int)``); the app parses the reply
from its first ``{`` as ``NVRResponseInfo`` and keeps it only when ``Esee-ID`` is
non-empty. Its ``Nonce`` is not returned.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

DISCOVERY_PORT = 12306
DISCOVERY_SOURCE_PORT = 57999
MULTICAST_GROUP = "224.2.3.4"
REQUEST_ID = 134489421
MAX_REPLY_BYTES = 8192
NVR_PORT = 9013
_NVR_CLIENT_ID = "CeCOlDpmTuzViBQDgbrPgFkfnyyzNabc"

_DEVICE_ID = re.compile(r"[A-Za-z0-9_-]{1,48}", re.ASCII)
_TEXT = re.compile(r"[\x20-\x7e]{1,64}", re.ASCII)


@dataclass(frozen=True)
class EseeCloudDiscoveryReply:
    device_id: str
    version: str | None
    device_type: str | None
    max_channel: int | None
    enable_channel: int | None


@dataclass(frozen=True)
class EseeCloudNvrReply:
    esee_id: str
    device_model: str | None
    device_type: str | None
    software_version: str | None
    channel_count: int | None
    http_port: int | None


def build_discovery_request() -> bytes:
    """Return the app's discovery JSON, byte for byte."""
    return (
        f'{{"fromApp":true,"requestID":{REQUEST_ID},"tokenID":"1473433878",'
        '"command":"discovery","version":"1.0"}'
    ).encode("ascii")


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and _TEXT.fullmatch(value) else None


def _channel_count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 256 else None


def parse_discovery_reply(data: bytes) -> EseeCloudDiscoveryReply | None:
    """Parse a camera reply; return None for requests, other IDs or bad JSON."""
    if len(data) > MAX_REPLY_BYTES:
        return None
    try:
        message = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    # The app ignores its own requests and replies to other request IDs.
    if (not isinstance(message, dict) or message.get("fromApp") is not False
            or message.get("requestID") != REQUEST_ID):
        return None
    device_id = message.get("deviceID")
    if not isinstance(device_id, str) or _DEVICE_ID.fullmatch(device_id) is None:
        return None
    devinfo = message.get("devinfo")
    if not isinstance(devinfo, dict):
        devinfo = {}
    return EseeCloudDiscoveryReply(
        device_id=device_id,
        version=_text(message.get("version")),
        device_type=_text(devinfo.get("deviceType")),
        max_channel=_channel_count(devinfo.get("maxChannel")),
        enable_channel=_channel_count(devinfo.get("enableChannel")),
    )


def build_nvr_request(cseq: int) -> bytes:
    """Return the app's new-NVR search request; ``cseq`` increments per round."""
    if type(cseq) is not int or not 0 <= cseq <= 0x7FFFFFFF:
        raise ValueError("cseq must be a non-negative 32-bit integer")
    return (
        f"SEARCH * HDS/1.1\r\nCSeq:{cseq}\r\nClient-ID:{_NVR_CLIENT_ID}\r\n"
        "Accept-Type:text/HDP\r\nContent-Length:13\r\nX-Search-Type:NVR\r\n"
        '{"Ver":"1.1"}'
    ).encode("ascii")


def parse_nvr_reply(data: bytes) -> EseeCloudNvrReply | None:
    """Parse an NVR reply from its first ``{``; return None without an Esee-ID."""
    if len(data) > MAX_REPLY_BYTES:
        return None
    start = data.find(b"{")
    if start < 0:
        return None
    try:
        message = json.loads(data[start:].decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(message, dict):
        return None
    esee_id = message.get("Esee-ID")
    if not isinstance(esee_id, str) or _DEVICE_ID.fullmatch(esee_id) is None:
        return None
    capabilities = message.get("Capabilities")
    http_port = capabilities.get("Http-Port") if isinstance(capabilities, dict) else None
    return EseeCloudNvrReply(
        esee_id=esee_id,
        device_model=_text(message.get("Device-Model")),
        device_type=_text(message.get("Device-Type")),
        software_version=_text(message.get("Software-Version")),
        channel_count=_channel_count(message.get("Channel-Cnt")),
        http_port=http_port if type(http_port) is int and 0 < http_port <= 65535 else None,
    )
