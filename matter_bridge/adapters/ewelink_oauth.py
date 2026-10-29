"""Official eWeLink OAuth 2.0 account import (https://dev.ewelink.cc).

This signs in to the user's own eWeLink account with the integrator's own App
ID and App Secret (registered for free at dev.ewelink.cc), lists their devices,
and extracts each device's LAN control key so the bridge can control them
locally. It is the documented OAuth 2.0 flow; it does not reuse the official
app's embedded credentials or impersonate it.

This module is pure request/response logic so it can be unit-tested. Network
I/O, the loopback redirect listener, and config writing live in
``tools/ewelink-import.py``. Access and refresh tokens are used only to list
devices and are never returned or persisted; only each device's own key is
kept, exactly as the existing ``ewelink_apikeys`` config already stores it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

# Login page and per-region v2 API hosts confirmed against eWeLink 5.29.1 and
# the official OAuth 2.0 documentation.
OAUTH_LOGIN_URL = "https://c2ccdn.coolkit.cc/oauth/index.html"
GRANT_TYPE = "authorization_code"
_NONCE_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_DEVICE_ID = re.compile(r"[A-Za-z0-9]{1,64}", re.ASCII)
_REGION = re.compile(r"[a-z]{2,8}", re.ASCII)
MAX_NAME_LENGTH = 128


@dataclass(frozen=True)
class EwelinkDevice:
    """A device listed from the cloud, with its LAN control key."""

    device_id: str
    device_key: str
    name: str
    uiid: int | None


def create_nonce() -> str:
    """Return an 8-character alphanumeric nonce, as the app's header builder does."""
    return "".join(secrets.choice(_NONCE_ALPHABET) for _ in range(8))


def _sign(message: bytes, app_secret: str) -> str:
    """Base64 HMAC-SHA256, the signature the app computes in ``MomokoAuth``."""
    digest = hmac.new(app_secret.encode("utf-8"), message, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def host_for_region(region: str) -> str:
    """Return the v2 API base URL for an eWeLink region code."""
    if _REGION.fullmatch(region) is None:
        raise ValueError(f"Unexpected eWeLink region: {region!r}")
    if region == "cn":
        return "https://cn-apia.coolkit.cn"
    if region in {"us", "eu", "as"}:
        return f"https://{region}-apia.coolkit.cc"
    raise ValueError(f"Unsupported eWeLink region: {region!r}")


def build_authorize_url(
    app_id: str, app_secret: str, redirect_url: str, state: str, *, seq: int, nonce: str,
) -> str:
    """Build the OAuth login URL the user opens to authorize this integration.

    The ``authorization`` parameter signs ``"{app_id}_{seq}"`` with the App
    Secret; ``seq`` is the current time in milliseconds.
    """
    if not app_id or not app_secret:
        raise ValueError("app_id and app_secret are required")
    authorization = _sign(f"{app_id}_{seq}".encode(), app_secret)
    query = urlencode({
        "clientId": app_id,
        "seq": str(seq),
        "authorization": authorization,
        "redirectUrl": redirect_url,
        "grantType": GRANT_TYPE,
        "state": state,
        "nonce": nonce,
    })
    return f"{OAUTH_LOGIN_URL}?{query}"


def token_request(
    app_id: str, app_secret: str, code: str, redirect_url: str, *, nonce: str,
) -> tuple[bytes, dict[str, str]]:
    """Return the POST body and headers for the ``/v2/user/oauth/token`` exchange.

    The body is signed verbatim, so callers must send exactly these bytes.
    """
    body = json.dumps(
        {"grantType": GRANT_TYPE, "code": code, "redirectUrl": redirect_url},
        separators=(",", ":"),
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-CK-Appid": app_id,
        "X-CK-Nonce": nonce,
        "Authorization": "Sign " + _sign(body, app_secret),
    }
    return body, headers


def device_list_headers(app_id: str, access_token: str, *, nonce: str) -> dict[str, str]:
    """Headers for the authenticated ``GET /v2/device/thing`` device listing."""
    return {
        "X-CK-Appid": app_id,
        "X-CK-Nonce": nonce,
        "Authorization": f"Bearer {access_token}",
    }


def _require_ok(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("eWeLink API returned a non-object response")
    error = payload.get("error")
    if error not in (0, None):
        message = payload.get("msg") or "unknown error"
        raise ValueError(f"eWeLink API error {error}: {message}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("eWeLink API response is missing a data object")
    return data


def parse_token_response(payload: Any) -> str:
    """Return the access token from a token-exchange response."""
    data = _require_ok(payload)
    token = data.get("accessToken")
    if not isinstance(token, str) or not token:
        raise ValueError("eWeLink token response has no accessToken")
    return token


def parse_device_list(payload: Any) -> list[EwelinkDevice]:
    """Extract controllable devices and their LAN keys from ``/v2/device/thing``.

    Devices without a usable id or local key are skipped rather than failing the
    whole import, since a single malformed entry should not block the rest.
    """
    data = _require_ok(payload)
    things = data.get("thingList")
    if not isinstance(things, list):
        raise ValueError("eWeLink device list is missing thingList")
    devices: list[EwelinkDevice] = []
    seen: set[str] = set()
    for thing in things:
        item = thing.get("itemData") if isinstance(thing, dict) else None
        if not isinstance(item, dict):
            continue
        device_id = item.get("deviceid")
        device_key = item.get("devicekey")
        if (not isinstance(device_id, str) or _DEVICE_ID.fullmatch(device_id) is None
                or not isinstance(device_key, str) or not device_key
                or device_id in seen):
            continue
        seen.add(device_id)
        extra = item.get("extra")
        uiid = extra.get("uiid") if isinstance(extra, dict) else None
        devices.append(EwelinkDevice(
            device_id=device_id,
            device_key=device_key,
            name=clean_name(item.get("name")) or device_id,
            uiid=uiid if type(uiid) is int else None,
        ))
    return devices


def clean_name(value: Any) -> str | None:
    """Return a display name with control characters removed, or None."""
    if not isinstance(value, str):
        return None
    name = "".join(ch for ch in value if ch.isprintable()).strip()[:MAX_NAME_LENGTH]
    return name or None


def merge_apikeys(
    config: dict[str, Any], devices: list[EwelinkDevice],
) -> tuple[dict[str, Any], int, int]:
    """Merge device keys and app names into a copy of ``config``.

    Keys go under ``ewelink_apikeys`` and the names given in the eWeLink app
    under ``ewelink_names``. Returns the new config plus counts of added and
    updated keys. Other config fields are left untouched.
    """
    merged = dict(config)
    existing = merged.get("ewelink_apikeys")
    apikeys: dict[str, str] = dict(existing) if isinstance(existing, dict) else {}
    existing_names = merged.get("ewelink_names")
    names: dict[str, str] = dict(existing_names) if isinstance(existing_names, dict) else {}
    added = updated = 0
    for device in devices:
        if device.device_id not in apikeys:
            added += 1
        elif apikeys[device.device_id] != device.device_key:
            updated += 1
        apikeys[device.device_id] = device.device_key
        if device.name != device.device_id:
            names[device.device_id] = device.name
    merged["ewelink_apikeys"] = apikeys
    merged["ewelink_names"] = names
    return merged, added, updated
