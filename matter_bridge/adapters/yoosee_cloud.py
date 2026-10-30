"""Yoosee account login and cloud inventory API.

The anonymous key derivation and request signatures here mirror the Yoosee
6.46.1 SDK static analysis documented in REVERSE_ENGINEERING.md. Video/P2P
session setup is a separate protocol and is not provided by this client.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from matter_bridge.core.storage import write_private_json

APP_ID = "d591b466644a0420e5f29aefb0cf0088"
APP_VERSION = "00.46.06.46"
API_BASE = "https://openapi-iot.cloudlinks.cn"
APP_BODY_ID = "adf33ae6eaa1439b48841fc330ffef11"
APP_BODY_TOKEN = "60ded395c2bdad3a2610ac6150550f551bb911eb6e6f7106c40c3bb1457bb07d"
PACKAGE_NAME = "com.yoosee"
PLATFORM = 1
CHANNEL = "googleplay"
_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_MASK32 = 0x7E18FC2D035A4B69


class YooseeCloudError(RuntimeError):
    """A safe, user-displayable account API error."""


def _json_bytes(value: dict[str, Any]) -> bytes:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    # Retrofit's default Gson writer uses HTML-safe JSON escaping.
    for character, escaped in {
        "<": r"\u003c", ">": r"\u003e", "&": r"\u0026",
        "=": r"\u003d", "'": r"\u0027", "\u2028": r"\u2028",
        "\u2029": r"\u2029",
    }.items():
        encoded = encoded.replace(character, escaped)
    return encoded.encode("utf-8")


def _version_number(version: str) -> str:
    parts = [int(part) for part in version.split(".")]
    if len(parts) != 4:
        raise ValueError("Yoosee version must have four components")
    packed = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    return str(packed & 0xFFFFFFFF)


APP_VERSION_PARAM = _version_number(APP_VERSION)


def _canonical(values: dict[str, str]) -> bytes:
    return "\n".join(f"{key}:{values[key]}" for key in sorted(values)).encode("utf-8")


def _base64_hmac_sha1(content: bytes, key: str) -> str:
    import base64
    digest = hmac.new(key.encode("utf-8"), content, hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii")


def _base32_nonce(value: int) -> str:
    value ^= _MASK32
    chars = []
    started = False
    for shift in range(60, -1, -5):
        digit = (value >> shift) & 31
        if digit or started:
            chars.append(_BASE32[digit])
            started = True
    return "".join(chars) or "0"


def _anonymous_keys(app_tag: str, timestamp: int) -> tuple[str, str]:
    """Port of iot_gen_app_anonymous_secure_key / iot_cal_app_anonymous_secure_key."""
    app_hash = 0
    for byte in app_tag.encode("utf-8"):
        app_hash = (app_hash * 131 + byte) & 0xFFFFFFFF
    nonce = (0xE000000000000000
             | ((app_hash & 0xFFFFFF) << 32)
             | (((timestamp // 15) & 0x7FFFFFF) << 5)
             | secrets.randbits(5))
    raw = bytearray(nonce.to_bytes(8, "little"))
    # xor_encrypt(data + 1, 6, null, 0): in-place, forward circular XOR.
    for index in range(1, 7):
        raw[index] ^= raw[1 + ((index - 1 + 1) % 6)]
    nonce = int.from_bytes(raw, "little")
    access_id = str(nonce)
    secret = hmac.new(app_tag.encode("utf-8"), _base32_nonce(nonce).encode("ascii"), hashlib.md5).hexdigest()
    return access_id, secret


def _mask_account(value: str) -> str:
    if "@" in value:
        name, domain = value.split("@", 1)
        return (name[:1] + "***@" + domain) if name else "***@" + domain
    return ("*" * max(0, len(value) - 4)) + value[-4:]


def _account_request_body(
    fields: dict[str, Any], *, region: str, session: dict[str, Any] | None,
) -> dict[str, Any]:
    access_id = session.get("accessId", "") if session else ""
    try:
        numeric_access_id = int(access_id)
    except (TypeError, ValueError):
        numeric_access_id = 0
    return {
        **fields,
        "language": "pt",
        "terminalOS": 3,
        "accessToken": session.get("accessToken", "") if session else "",
        "pkgName": PACKAGE_NAME,
        "appVersion": APP_VERSION_PARAM,
        "appName": "Yoosee",
        "appId": APP_BODY_ID,
        "appToken": APP_BODY_TOKEN,
        "apiVersion": 2,
        "platform": PLATFORM,
        "channel": CHANNEL,
        "region": region,
        "accessId": numeric_access_id,
        "funcSupport": 7,
    }


class YooseeCloud:
    """Local account session and paginated cloud device inventory."""

    def __init__(self, session_path: Path | None) -> None:
        self.session_path = session_path
        self._session = self._load_session()

    def _load_session(self) -> dict[str, Any] | None:
        if self.session_path is None:
            return None
        try:
            data = json.loads(self.session_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not all(
            isinstance(data.get(key), str) and data[key]
            for key in ("accessId", "accessToken", "account", "loginRegion")
        ):
            return None
        return data

    def _persist_session(self) -> None:
        if self.session_path is not None and self._session is not None:
            write_private_json(self.session_path, self._session)

    @property
    def connected(self) -> bool:
        return self._session is not None

    def public_status(self) -> dict[str, Any]:
        session = self._session
        if session is None:
            return {"connected": False, "account": None}
        return {
            "connected": True,
            "account": _mask_account(session["account"]),
            "login_region": session["loginRegion"],
            "device_count": session.get("deviceCount"),
        }

    async def _request(
        self, path: str, body: dict[str, Any], *, anonymous: bool,
        area: str = "", unique_id: str = "",
    ) -> dict[str, Any]:
        if not path.startswith("/openapi/"):
            raise YooseeCloudError("Endpoint Yoosee inválido")
        host = urlsplit(API_BASE).hostname or "openapi-iot.cloudlinks.cn"
        now = int(time.time())
        nonce = str(secrets.randbelow(2**31))
        app_tag = APP_ID + APP_VERSION_PARAM
        if anonymous:
            access_id, secret = _anonymous_keys(app_tag, now)
        else:
            if self._session is None:
                raise YooseeCloudError("Conecte sua conta Yoosee primeiro")
            access_id = self._session["accessId"]
            secret = self._session["accessToken"]

        payload = _json_bytes(body)
        signed = {
            "host": host,
            "x-iotvideo-accessid": access_id,
            "x-iotvideo-nonce": nonce,
            "x-iotvideo-timestamp": str(now),
            "payload": hashlib.sha256(payload).hexdigest(),
        }
        if anonymous:
            signed["x-iotvideo-appid"] = APP_ID
            signed["x-iotvideo-appver"] = APP_VERSION_PARAM
        signature = _base64_hmac_sha1(_canonical(signed), secret)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-iotvideo-accessid": access_id,
            "x-iotvideo-nonce": nonce,
            "x-iotvideo-timestamp": str(now),
            "x-iotvideo-area": area,
            "x-iotvideo-appver": APP_VERSION_PARAM,
            "x-iotvideo-appid": APP_ID,
            "x-iotvideo-signature": signature,
            "x-iotvideo-uniqueid": (
                unique_id or str(self._session.get("uniqueId", ""))
                if self._session else unique_id
            ),
        }
        if anonymous:
            headers["x-iotvideo-anonymous"] = "anonymous"
        timeout = aiohttp.ClientTimeout(total=20)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as client:
                async with client.post(API_BASE + path, data=payload, headers=headers, allow_redirects=False) as response:
                    if response.status < 200 or response.status >= 300:
                        raise YooseeCloudError(f"Servidor Yoosee respondeu HTTP {response.status}")
                    result = await response.json(content_type=None)
        except YooseeCloudError:
            raise
        except (aiohttp.ClientError, TimeoutError, ValueError):
            raise YooseeCloudError("Não foi possível comunicar com o serviço Yoosee") from None
        if not isinstance(result, dict):
            raise YooseeCloudError("Resposta inesperada do serviço Yoosee")
        return result

    async def login(
        self, *, account: str, password: str, login_region: str,
        mode: str = "email", mobile_area: str = "",
    ) -> dict[str, Any]:
        if mode not in {"email", "mobile", "userId"}:
            raise YooseeCloudError("Escolha um tipo de conta válido")
        if not account.strip() or not password or not login_region.strip():
            raise YooseeCloudError("Preencha conta, senha e região")
        unique_id = str(uuid.uuid4())
        field = {"email": "email", "mobile": "mobile", "userId": "userId"}[mode]
        hashed_password = hashlib.md5(password.encode("utf-8")).hexdigest()
        if mode == "mobile":
            if not mobile_area.strip():
                raise YooseeCloudError("Informe o código do país para login por telefone")
            fields: dict[str, Any] = {
                "mobile": account.strip(), "mobileArea": mobile_area.strip(),
                "loginMode": mode, "pwd": hashed_password,
                "uniqueId": unique_id, "loginRegion": login_region.strip(),
            }
        else:
            fields = {
                field: account.strip(), "loginMode": mode, "pwd": hashed_password,
                "uniqueId": unique_id, "loginRegion": login_region.strip(),
            }
        payload = _account_request_body(
            fields, region=login_region.strip(), session=None,
        )

        response = await self._request(
            "/openapi/app/user/login/account", payload, anonymous=True,
            # The SDK's area header is unset before authentication; region is
            # carried separately in the request body and loginRegion field.
            area="", unique_id=unique_id,
        )
        data = response.get("data", response)
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                pass
        if not isinstance(data, dict) and isinstance(response.get("result"), dict):
            data = response["result"]
        if not isinstance(data, dict):
            message = response.get("msg") or response.get("message")
            if isinstance(message, str) and message:
                raise YooseeCloudError(message[:200])
            keys = ", ".join(sorted(str(key) for key in response)[:8])
            raise YooseeCloudError(
                f"Resposta de login inválida (campos: {keys or 'nenhum'})"
            )
        access_id = data.get("accessId") or data.get("accessID")
        access_token = data.get("accessToken") or data.get("token")
        if not isinstance(access_id, str) or not isinstance(access_token, str):
            message = response.get("msg") or response.get("message")
            if isinstance(message, str) and message:
                raise YooseeCloudError(message[:200])
            raise YooseeCloudError("O Yoosee não retornou uma sessão válida")
        self._session = {
            "accessId": access_id,
            "accessToken": access_token,
            "account": account.strip(),
            "loginRegion": login_region.strip(),
            "uniqueId": unique_id,
            "userID": data.get("userID") or data.get("userId"),
            "sessionID": data.get("sessionID"),
            "sessionID2": data.get("sessionID2"),
            "area": data.get("area") or login_region.strip(),
            "region": data.get("region") or login_region.strip(),
            "deviceCount": None,
        }
        self._persist_session()
        return self.public_status()

    async def devices(self) -> list[dict[str, Any]]:
        session = self._session
        if session is None:
            raise YooseeCloudError("Conecte sua conta Yoosee primeiro")
        all_devices: list[dict[str, Any]] = []
        last_id = ""
        for _ in range(100):
            response = await self._request(
                "/openapi/v2/user/device/list",
                _account_request_body(
                    {"lastDeviceId": last_id},
                    region=str(session.get("region", session["loginRegion"])),
                    session=session,
                ),
                anonymous=False, area=str(session.get("area", "")),
            )
            data = response.get("data", response)
            if not isinstance(data, dict):
                raise YooseeCloudError("Resposta de dispositivos inválida")
            devices = data.get("deviceList", [])
            if not isinstance(devices, list):
                raise YooseeCloudError("Lista de dispositivos inválida")
            for device in devices:
                if not isinstance(device, dict):
                    continue
                dev_id = device.get("devId")
                if not isinstance(dev_id, (str, int)):
                    continue
                all_devices.append({
                    "device_id": str(dev_id),
                    "name": str(device.get("remarkName") or dev_id),
                    "category": device.get("deviceCate"),
                    "permission": device.get("permission"),
                    "relation": device.get("relation"),
                    "online": device.get("online") if isinstance(device.get("online"), bool) else None,
                })
            next_id = devices[-1].get("devId") if devices and isinstance(devices[-1], dict) else None
            if not devices or data.get("count", len(devices)) <= len(all_devices) or next_id is None or str(next_id) == last_id:
                break
            last_id = str(next_id)
        session["deviceCount"] = len(all_devices)
        self._persist_session()
        return all_devices

    def logout(self) -> None:
        self._session = None
        if self.session_path is not None:
            try:
                self.session_path.unlink()
            except FileNotFoundError:
                pass
