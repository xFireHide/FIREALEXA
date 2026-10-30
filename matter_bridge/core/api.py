"""Local HTTP API for inventory, state and LAN commands."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
from collections.abc import Callable
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit
from pathlib import Path

import aiohttp
from aiohttp import web

from matter_bridge.core.base_adapter import BaseAdapter, DeviceInfo, DeviceState
from matter_bridge.core.registry import DeviceRegistry
from matter_bridge.adapters.ewelink_protocol import cover_calibrated
from matter_bridge.core.camera_media import CameraMedia, CameraMediaBusy
from matter_bridge.adapters.onvif_adapter import OnvifAdapter
from matter_bridge.adapters.eseecloud_adapter import (
    EseeCloudAdapter,
    EseeCloudStreamBusyError,
)
from matter_bridge.adapters.eseecloud_protocol import (
    EseeCloudMediaReader,
    EseeCloudProtocolError,
)
from matter_bridge.adapters.yoosee_cloud import YooseeCloud, YooseeCloudError

logger = logging.getLogger(__name__)

_SENSITIVE_JSON_KEYS = {
    "accesstoken", "apikey", "authtoken", "authorization", "credential",
    "credentials", "devicekey", "devicetoken", "encryptionkey", "key",
    "localkey", "networkkey", "password", "privatekey", "refreshtoken",
    "secret", "sessionkey", "token",
}


def _is_sensitive_json_key(value: str) -> bool:
    normalized = value.casefold().replace("-", "").replace("_", "")
    return normalized in _SENSITIVE_JSON_KEYS or normalized.endswith((
        "token", "password", "secret", "credential", "apikey", "sessionkey",
        "privatekey", "encryptionkey", "devicekey", "localkey", "networkkey",
        "accesskey", "authkey", "aeskey", "signingkey",
    ))


def _json_safe(value: Any) -> Any:
    """Normalize protocol data to strict JSON values before returning it.

    Binary and unsupported runtime objects become null, while secret-looking
    fields are omitted recursively so protocol payloads cannot expose keys.
    """
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {
            key: _json_safe(item)
            for key, item in value.items()
            if isinstance(key, str) and not _is_sensitive_json_key(key)
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return None


def _number_in_range(value: Any, minimum: float, maximum: float) -> int | float | None:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not minimum <= value <= maximum):
        return None
    try:
        if not math.isfinite(value):
            return None
    except OverflowError:
        return None
    return value


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _ewelink_uiid(device: DeviceInfo) -> int | None:
    if device.brand != "ewelink":
        return None
    value = device.raw_metadata.get("type")
    if type(value) is int and 0 <= value <= 65535:
        return value
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 5:
        parsed = int(value)
        if parsed <= 65535:
            return parsed
    return None


def _device_json(
    device: DeviceInfo,
    state: DeviceState | None,
    adapter: BaseAdapter | None = None,
) -> dict[str, Any]:
    device_type = device.device_type.name
    params = state.raw.get("params") if state is not None else None
    if _is_dualr3(device) and isinstance(params, dict) and params.get("workMode") == 2:
        device_type = "WINDOW_COVERING"
    result = {
        "brand": device.brand,
        "device_id": device.device_id,
        "name": device.name or device.model or device.device_id,
        "model": device.model,
        "uiid": _ewelink_uiid(device),
        "ip": device.ip,
        "port": device.port,
        "type": device_type,
        "online": _optional_bool(state.online) if state else None,
        "state": (_json_safe({
            "on": _optional_bool(state.on),
            "brightness": _number_in_range(state.brightness, 0, 100),
            "color_temp": _number_in_range(state.color_temp, 1, 1000),
            "hue": _number_in_range(state.hue, 0, 360),
            "saturation": _number_in_range(state.saturation, 0, 100),
            "temperature": _number_in_range(state.temperature, -273.15, 327.67),
            "humidity": _number_in_range(state.humidity, 0, 100),
            "cover_position": _number_in_range(state.cover_position, 0, 100),
            "cover_motion": (
                state.cover_motion
                if state.cover_motion in {"opening", "closing", "stopped"}
                else None
            ),
            "cover_calibrated": (
                cover_calibrated(params) if _is_dualr3(device) else None
            ),
            "contact_open": _optional_bool(state.contact_open),
            "motion_detected": _optional_bool(state.motion_detected),
            "raw": state.raw,
        }) if state else None),
    }
    if device.brand == "onvif":
        discovery_protocol = device.raw_metadata.get("discovery_protocol")
        if discovery_protocol not in {"onvif_ws_discovery", "xm_udp_8899", "gwell_lan_8899"}:
            discovery_protocol = None
        vendor_hint = (
            "Yoosee/XM (unverified)"
            if discovery_protocol == "xm_udp_8899"
            and device.raw_metadata.get("vendor_hint") == "Yoosee/XM (unverified)"
            else None
        )
        gwell_id = device.raw_metadata.get("gwell_device_id")
        result["camera"] = _json_safe({
            "authenticated": device.raw_metadata.get("onvif_authenticated") is True,
            "profiles": (
                adapter.public_profiles(device.device_id)
                if isinstance(adapter, OnvifAdapter)
                and device.raw_metadata.get("onvif_authenticated") is True else []
            ),
            "discovery_protocol": discovery_protocol,
            "vendor_hint": vendor_hint,
            "gwell": {
                "device_id": gwell_id,
                "type": device.raw_metadata.get("gwell_type"),
                "sub_type": device.raw_metadata.get("gwell_sub_type"),
                "onvif_port_open": device.raw_metadata.get("onvif_port_open"),
            } if type(gwell_id) is int else None,
        })
    elif device.brand == "eseecloud":
        result["camera"] = _json_safe({
            "stream_channel": device.raw_metadata.get("stream_channel"),
            "discovery_protocol": device.raw_metadata.get("discovery_protocol"),
            "stream_available": (
                state.raw.get("stream_available") is True if state is not None else False
            ),
            "lan_discovery": {
                "device_id": device.raw_metadata.get("eseecloud_device_id"),
                "device_type": device.raw_metadata.get("eseecloud_device_type"),
                "version": device.raw_metadata.get("eseecloud_version"),
                "max_channel": device.raw_metadata.get("eseecloud_max_channel"),
            } if isinstance(device.raw_metadata.get("eseecloud_device_id"), str) else None,
        })
    return result


def _is_dualr3(device: DeviceInfo) -> bool:
    return (
        device.brand == "ewelink"
        and (
            _ewelink_uiid(device) == 126
            or device.model in {"UIID_126", "DUALR3"}
        )
    )


class LocalAPI:
    """Owns an aiohttp server and routes requests to registered LAN adapters."""

    def __init__(
        self,
        registry: DeviceRegistry,
        adapters: list[BaseAdapter],
        host: str = "127.0.0.1",
        port: int = 8765,
        allow_remote_commands: bool = False,
        matter_status: Callable[[], str] | None = None,
        matter_pairing: Callable[[], dict[str, object]] | None = None,
        camera_runtime_path: Path | None = None,
        yoosee_session_path: Path | None = None,
    ) -> None:
        self.registry = registry
        self.adapters = {adapter.BRAND: adapter for adapter in adapters}
        self.host, self.port = host, port
        self.allow_remote_commands = allow_remote_commands
        self.matter_status = matter_status
        self.matter_pairing = matter_pairing
        self._runner: web.AppRunner | None = None
        self._lifecycle_lock = asyncio.Lock()
        self._camera_runtime_path = camera_runtime_path
        self._camera_media = CameraMedia(camera_runtime_path)
        self._yoosee = YooseeCloud(yoosee_session_path)

    async def yoosee_status(self, request: web.Request) -> web.Response:
        self._check_camera_client(request)
        return web.json_response(self._yoosee.public_status(), headers={"Cache-Control": "no-store"})

    async def yoosee_login(self, request: web.Request) -> web.Response:
        self._check_camera_client(request)
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType(text="JSON é obrigatório")
        try:
            body = await request.json()
        except (ValueError, TypeError):
            raise web.HTTPBadRequest(text="JSON inválido") from None
        if (
            not isinstance(body, dict)
            or set(body) - {"account", "password", "login_region", "mode", "mobile_area"}
            or not all(
                isinstance(body.get(field), str)
                for field in ("account", "password", "login_region")
            )
            or ("mode" in body and not isinstance(body["mode"], str))
            or ("mobile_area" in body and not isinstance(body["mobile_area"], str))
        ):
            raise web.HTTPBadRequest(text="Informe account, password e login_region")
        try:
            status = await self._yoosee.login(
                account=body["account"], password=body["password"],
                login_region=body["login_region"], mode=body.get("mode", "email"),
                mobile_area=body.get("mobile_area", ""),
            )
        except YooseeCloudError as exc:
            raise web.HTTPBadGateway(text=str(exc)) from None
        except Exception:
            logger.warning("Yoosee login failed", exc_info=True)
            raise web.HTTPBadGateway(text="Falha ao entrar na conta Yoosee") from None
        return web.json_response(status, headers={"Cache-Control": "no-store"})

    async def yoosee_devices(self, request: web.Request) -> web.Response:
        self._check_camera_client(request)
        try:
            devices = await self._yoosee.devices()
        except YooseeCloudError as exc:
            raise web.HTTPBadGateway(text=str(exc)) from None
        except Exception:
            logger.warning("Yoosee device listing failed", exc_info=True)
            raise web.HTTPBadGateway(text="Falha ao listar dispositivos Yoosee") from None
        return web.json_response(devices, headers={"Cache-Control": "no-store"})

    async def yoosee_logout(self, request: web.Request) -> web.Response:
        self._check_camera_client(request)
        self._yoosee.logout()
        return web.json_response({"connected": False}, headers={"Cache-Control": "no-store"})

    def _check_camera_client(self, request: web.Request) -> None:
        self._check_loopback_origin(request)
        # Defend the localhost signaling service against DNS rebinding and
        # cross-origin browser requests, even when remote device control is enabled.
        try:
            host = urlsplit(f"http://{request.host}").hostname
            allowed = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except (ValueError, TypeError):
            allowed = False
        if not allowed:
            raise web.HTTPForbidden(text="Camera signaling requires a loopback Host")
        origin = request.headers.get("Origin")
        if origin is not None and origin != f"{request.scheme}://{request.host}":
            raise web.HTTPForbidden(text="Cross-origin camera signaling is forbidden")

    async def create_camera_session(self, request: web.Request) -> web.Response:
        self._check_camera_client(request)
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType(text="JSON signaling is required")
        try:
            body = await request.json()
        except (ValueError, TypeError):
            raise web.HTTPBadRequest(text="Invalid JSON") from None
        if (not isinstance(body, dict) or "profile" not in body or set(body) - {"profile", "sdp", "audio"}
                or not isinstance(body["profile"], str) or not 1 <= len(body["profile"]) <= 256
                or ("audio" in body and not isinstance(body["audio"], bool))
                or ("sdp" in body and (not isinstance(body["sdp"], str)
                    or not 1 <= len(body["sdp"].encode()) <= 65536))):
            raise web.HTTPBadRequest(text="A profile and optional SDP offer are required")
        adapter = self.adapters.get("onvif")
        if not isinstance(adapter, OnvifAdapter):
            raise web.HTTPNotFound(text="No ONVIF adapter is available")
        device_id = request.match_info["device_id"]
        if self._device("onvif", device_id) is None:
            raise web.HTTPNotFound(text="Unknown ONVIF camera")
        try:
            source = adapter.media_source(device_id, body["profile"])
        except (ValueError, KeyError):
            raise web.HTTPConflict(text="An authenticated RTSP profile is required") from None
        if body.get("audio") is True and source.get("audio") is not True:
            raise web.HTTPConflict(text="This ONVIF profile does not advertise audio")
        if "audio" in body:
            source["audio"] = body["audio"]
        try:
            result = await self._camera_media.create(source, body.get("sdp"))
        except CameraMediaBusy:
            raise web.HTTPTooManyRequests(text="Camera session limit reached") from None
        except (RuntimeError, OSError):
            raise web.HTTPBadGateway(text="Camera video negotiation failed") from None
        return web.json_response(result, status=201, headers={"Cache-Control": "no-store"})

    async def camera_ice(self, request: web.Request) -> web.Response:
        self._check_camera_client(request)
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType(text="JSON signaling is required")
        try:
            body = await request.json()
            if not isinstance(body, dict) or set(body) != {"candidate"}:
                raise ValueError()
            candidate = body["candidate"]
            if candidate is not None and (
                not isinstance(candidate, dict)
                or set(candidate) - {"candidate", "sdpMid", "sdpMLineIndex", "usernameFragment"}
                or not isinstance(candidate.get("candidate"), str)
                or len(str(candidate)) > 4096
            ):
                raise ValueError()
        except (ValueError, TypeError):
            raise web.HTTPBadRequest(text="Invalid ICE candidate") from None
        try:
            await self._camera_media.ice(request.match_info["session_id"], candidate)
        except KeyError:
            raise web.HTTPNotFound(text="Unknown camera session") from None
        except RuntimeError:
            raise web.HTTPBadGateway(text="Camera ICE exchange failed") from None
        return web.Response(status=204)

    async def close_camera_session(self, request: web.Request) -> web.Response:
        self._check_camera_client(request)
        await self._camera_media.close(request.match_info["session_id"])
        return web.Response(status=204)

    async def camera_session_status(self, request: web.Request) -> web.Response:
        self._check_camera_client(request)
        active = self._camera_media.is_active(request.match_info["session_id"])
        return web.json_response({"active": active}, headers={"Cache-Control": "no-store"})

    async def camera_answer(self, request: web.Request) -> web.Response:
        self._check_camera_client(request)
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType(text="JSON signaling is required")
        try:
            body = await request.json()
            if (not isinstance(body, dict) or set(body) != {"sdp"}
                    or not isinstance(body["sdp"], str)
                    or not 1 <= len(body["sdp"].encode()) <= 65536):
                raise ValueError()
        except (ValueError, TypeError):
            raise web.HTTPBadRequest(text="Invalid SDP answer") from None
        try:
            await self._camera_media.answer(request.match_info["session_id"], body["sdp"])
        except KeyError:
            raise web.HTTPNotFound(text="Unknown camera session") from None
        except RuntimeError:
            raise web.HTTPBadGateway(text="Camera SDP exchange failed") from None
        return web.Response(status=204)

    def _adapter(self, device: DeviceInfo) -> BaseAdapter:
        try:
            return self.adapters[device.brand]
        except KeyError as exc:
            raise web.HTTPNotFound(text="No adapter for device brand") from exc

    def _device(self, brand: str, device_id: str) -> DeviceInfo | None:
        device = self.registry.get(brand, device_id)
        if device is not None:
            return device
        adapter = self.adapters.get(brand)
        return adapter.get_device(device_id) if adapter is not None else None

    async def _refresh_state(self, adapter: BaseAdapter, device_id: str) -> DeviceState:
        """Refresh and publish state, marking stale cached values unreachable on errors."""
        try:
            state = await adapter.get_state(device_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("State refresh failed for %s:%s", adapter.BRAND, device_id,
                           exc_info=True)
            cached = adapter.get_cached_state(device_id)
            state = replace(cached, online=False) if cached is not None else DeviceState()
        await adapter.publish_state(device_id, state)
        return adapter.get_cached_state(device_id) or state

    def _check_command_origin(self, request: web.Request) -> None:
        if self.allow_remote_commands:
            return
        self._check_loopback_origin(request)

    @staticmethod
    def _check_loopback_origin(request: web.Request) -> None:
        remote = request.remote
        try:
            if remote is None or not ipaddress.ip_address(remote).is_loopback:
                raise web.HTTPForbidden(text="This endpoint is limited to loopback clients")
        except ValueError as exc:
            raise web.HTTPForbidden(text="Unable to verify command client address") from exc

    async def health(self, request: web.Request) -> web.Response:
        adapters = {
            brand: {"running": adapter.running, "device_count": len(adapter.devices)}
            for brand, adapter in self.adapters.items()
        }
        status: dict[str, Any] = {
            "ok": True,
            "adapters": adapters,
        }
        matter = self.matter_status() if self.matter_status is not None else None
        if self.matter_status is not None:
            status["matter"] = matter
        status["ready"] = (
            all(adapter["running"] for adapter in adapters.values())
            and matter in {None, "ready", "disabled"}
        )
        return web.json_response(status)

    async def list_devices(self, request: web.Request) -> web.Response:
        devices_by_key = {
            (device.brand, device.device_id): device for device in self.registry.all_devices()
        }
        for brand, adapter in self.adapters.items():
            for device in adapter.devices.values():
                devices_by_key.setdefault((brand, device.device_id), device)
        devices = list(devices_by_key.values())
        result = []
        for device in devices:
            adapter = self.adapters.get(device.brand)
            if adapter is None:
                logger.warning(
                    "Omitting stored device with unsupported brand %s (%s)",
                    device.brand, device.device_id,
                )
                continue
            state = adapter.get_cached_state(device.device_id)
            if device.raw_metadata.get("virtual_ir") is True:
                state = await self._refresh_state(adapter, device.device_id)
            result.append(_device_json(device, state, adapter))
        return web.json_response(result)

    async def get_state(self, request: web.Request) -> web.Response:
        brand, device_id = request.match_info["brand"], request.match_info["device_id"]
        device = self._device(brand, device_id)
        if device is None:
            raise web.HTTPNotFound(text="Unknown device")
        adapter = self._adapter(device)
        state = await self._refresh_state(adapter, device_id)
        return web.json_response(_device_json(device, state, adapter))

    async def get_camera_snapshot(self, request: web.Request) -> web.Response:
        self._check_loopback_origin(request)
        brand = request.match_info["brand"]
        device_id = request.match_info["device_id"]
        profile_token = request.query.get("profile", "")
        if not profile_token or len(profile_token) > 256:
            raise web.HTTPBadRequest(text="A valid ONVIF profile query parameter is required")
        device = self._device(brand, device_id)
        if device is None:
            raise web.HTTPNotFound(text="Unknown device")
        if brand != "onvif" or device.device_type.name != "CAMERA":
            raise web.HTTPBadRequest(text="Snapshots are supported only for ONVIF cameras")
        adapter = self.adapters.get(brand)
        if not isinstance(adapter, OnvifAdapter):
            raise web.HTTPNotFound(text="No ONVIF adapter is available")
        if (not adapter.has_credentials(device_id)
                or device.raw_metadata.get("onvif_authenticated") is not True):
            raise web.HTTPConflict(text="Configure valid local ONVIF credentials first")
        resolved_profile = adapter.resolve_profile_selector(device_id, profile_token)
        if resolved_profile is None:
            raise web.HTTPNotFound(text="Unknown ONVIF media profile")
        try:
            image = await adapter.get_snapshot(device_id, resolved_profile)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Camera snapshot URIs may carry short-lived query credentials.
            # Do not emit exception strings or tracebacks that could include them.
            logger.warning("ONVIF snapshot failed for %s", device_id)
            raise web.HTTPBadGateway(text="Could not retrieve camera snapshot") from None
        return web.Response(
            body=image,
            content_type="image/jpeg",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    async def get_eseecloud_stream(self, request: web.Request) -> web.StreamResponse:
        """Proxy the configured camera's raw framed media to loopback clients."""
        self._check_loopback_origin(request)
        device_id = request.match_info["device_id"]
        device = self._device("eseecloud", device_id)
        if device is None:
            raise web.HTTPNotFound(text="Unknown EseeCloud camera")
        adapter = self.adapters.get("eseecloud")
        if not isinstance(adapter, EseeCloudAdapter):
            raise web.HTTPNotFound(text="EseeCloud stream adapter is unavailable")
        if not adapter.has_stream(device_id):
            raise web.HTTPNotFound(text="No local stream is configured for this EseeCloud camera")
        downstream = web.StreamResponse(headers={
            "Content-Type": "application/octet-stream",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        })
        try:
            async with adapter.stream(device_id) as upstream:
                media = EseeCloudMediaReader(upstream.content)
                preamble = await media.read_preamble()
                await adapter.mark_stream_valid(device_id, media.media_tracks)
                try:
                    await downstream.prepare(request)
                    await downstream.write(preamble)
                except asyncio.CancelledError:
                    raise
                except (ConnectionResetError, BrokenPipeError):
                    logger.debug("EseeCloud stream client disconnected for %s", device_id)
                else:
                    frames = media.frames()
                    while True:
                        try:
                            frame = await anext(frames)
                        except StopAsyncIteration:
                            # A clean EOF also means the configured live source ended.
                            await adapter.mark_offline(device_id)
                            break
                        except (aiohttp.ClientError, asyncio.TimeoutError,
                                EseeCloudProtocolError):
                            logger.warning("EseeCloud source stream failed for %s", device_id)
                            await adapter.mark_offline(device_id)
                            break
                        try:
                            await downstream.write(frame)
                        except asyncio.CancelledError:
                            raise
                        except (ConnectionResetError, BrokenPipeError):
                            logger.debug(
                                "EseeCloud stream client disconnected for %s", device_id
                            )
                            break
                try:
                    await downstream.write_eof()
                except (ConnectionResetError, BrokenPipeError, RuntimeError):
                    pass
        except asyncio.CancelledError:
            raise
        except EseeCloudStreamBusyError:
            raise web.HTTPServiceUnavailable(text="Camera already has two active viewers") from None
        except (aiohttp.ClientError, asyncio.TimeoutError, EseeCloudProtocolError,
                KeyError, RuntimeError):
            await adapter.mark_offline(device_id)
            logger.warning("Could not open configured EseeCloud stream for %s", device_id)
            raise web.HTTPBadGateway(text="Could not open EseeCloud local stream") from None
        return downstream

    async def get_eseecloud_stream_info(self, request: web.Request) -> web.Response:
        """Read only the configured source preamble and report supported codecs."""
        self._check_loopback_origin(request)
        device_id = request.match_info["device_id"]
        device = self._device("eseecloud", device_id)
        if device is None:
            raise web.HTTPNotFound(text="Unknown EseeCloud camera")
        adapter = self.adapters.get("eseecloud")
        if not isinstance(adapter, EseeCloudAdapter):
            raise web.HTTPNotFound(text="EseeCloud stream adapter is unavailable")
        if not adapter.has_stream(device_id):
            raise web.HTTPNotFound(text="No local stream is configured for this EseeCloud camera")
        try:
            async with adapter.stream(device_id) as upstream:
                media = EseeCloudMediaReader(upstream.content)
                await media.read_preamble()
                await adapter.mark_stream_valid(device_id, media.media_tracks)
                return web.json_response({
                    "device_id": device_id,
                    "tracks": list(media.media_tracks),
                })
        except asyncio.CancelledError:
            raise
        except EseeCloudStreamBusyError:
            raise web.HTTPServiceUnavailable(
                text="Camera already has two active viewers"
            ) from None
        except (aiohttp.ClientError, asyncio.TimeoutError, EseeCloudProtocolError,
                KeyError, RuntimeError):
            await adapter.mark_offline(device_id)
            logger.warning("Could not inspect configured EseeCloud stream for %s", device_id)
            raise web.HTTPBadGateway(text="Could not inspect EseeCloud local stream") from None

    async def set_state(self, request: web.Request) -> web.Response:
        self._check_command_origin(request)
        brand, device_id = request.match_info["brand"], request.match_info["device_id"]
        device = self._device(brand, device_id)
        if device is None:
            raise web.HTTPNotFound(text="Unknown device")
        try:
            payload = await request.json()
        except (ValueError, TypeError) as exc:
            raise web.HTTPBadRequest(text="Expected a JSON object") from exc
        if not isinstance(payload, dict) or not payload:
            raise web.HTTPBadRequest(text="Expected a non-empty JSON object")
        allowed = {
            "on", "brightness", "channel", "hue", "saturation", "color_temp",
            "ir_data", "ptz", "cover",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise web.HTTPBadRequest(text=f"Unsupported fields: {', '.join(sorted(unknown))}")
        if "on" in payload and not isinstance(payload["on"], bool):
            raise web.HTTPBadRequest(text="on must be boolean")
        if "brightness" in payload and (
            not isinstance(payload["brightness"], int)
            or isinstance(payload["brightness"], bool)
            or not 0 <= payload["brightness"] <= 100
        ):
            raise web.HTTPBadRequest(text="brightness must be an integer from 0 to 100")
        if "hue" in payload and (
            not isinstance(payload["hue"], (int, float))
            or isinstance(payload["hue"], bool)
            or not 0 <= payload["hue"] <= 360
            or not math.isfinite(payload["hue"])
        ):
            raise web.HTTPBadRequest(text="hue must be a finite number from 0 to 360")
        if "saturation" in payload and (
            not isinstance(payload["saturation"], (int, float))
            or isinstance(payload["saturation"], bool)
            or not 0 <= payload["saturation"] <= 100
            or not math.isfinite(payload["saturation"])
        ):
            raise web.HTTPBadRequest(text="saturation must be a finite number from 0 to 100")
        if "color_temp" in payload and (
            not isinstance(payload["color_temp"], int)
            or isinstance(payload["color_temp"], bool)
            or not 154 <= payload["color_temp"] <= 500
        ):
            raise web.HTTPBadRequest(text="color_temp must be an integer from 154 to 500 mireds")
        if "channel" in payload and (
            not isinstance(payload["channel"], int)
            or isinstance(payload["channel"], bool)
            or not 0 <= payload["channel"] <= 31
        ):
            raise web.HTTPBadRequest(text="channel must be an integer from 0 to 31")
        if "ir_data" in payload:
            ir_data = payload["ir_data"]
            if not isinstance(ir_data, str) or not ir_data or len(ir_data) > 8192:
                raise web.HTTPBadRequest(
                    text="ir_data must be a non-empty hex string of at most 8192 chars"
                )
            try:
                payload["ir_data"] = bytes.fromhex(ir_data)
            except ValueError as exc:
                raise web.HTTPBadRequest(text="ir_data must contain valid hexadecimal") from exc
            if not payload["ir_data"]:
                raise web.HTTPBadRequest(text="ir_data cannot be empty")

        if "ptz" in payload:
            command = payload["ptz"]
            if brand != "onvif" or set(payload) != {"ptz"} or not isinstance(command, dict):
                raise web.HTTPBadRequest(text="ptz commands are supported only for ONVIF cameras")
            if set(command) - {"direction", "duration_ms", "speed"}:
                raise web.HTTPBadRequest(text="Unsupported ONVIF PTZ command fields")
            direction = command.get("direction")
            if not isinstance(direction, str) or direction not in {
                "up", "down", "left", "right", "up_left", "up_right",
                "down_left", "down_right", "stop",
            }:
                raise web.HTTPBadRequest(text="Invalid ONVIF PTZ direction")
            duration = command.get("duration_ms", 500)
            if (not isinstance(duration, int) or isinstance(duration, bool)
                    or not 100 <= duration <= 5000):
                raise web.HTTPBadRequest(text="duration_ms must be an integer from 100 to 5000")
            speed = command.get("speed", 0.5)
            if (not isinstance(speed, (int, float)) or isinstance(speed, bool)
                    or not 0.05 <= speed <= 1 or not math.isfinite(speed)):
                raise web.HTTPBadRequest(text="speed must be a finite number from 0.05 to 1")

        if "cover" in payload:
            command = payload["cover"]
            direction = command.get("direction") if isinstance(command, dict) else None
            position = command.get("position") if isinstance(command, dict) else None
            valid_direction = (
                isinstance(command, dict) and set(command) == {"direction"}
                and isinstance(direction, str) and direction in {"open", "close", "stop"}
            )
            valid_position = (
                isinstance(command, dict) and set(command) == {"position"}
                and type(position) is int and 0 <= position <= 100
            )
            if (brand != "ewelink" or set(payload) != {"cover"}
                    or not (valid_direction or valid_position)):
                raise web.HTTPBadRequest(
                    text="cover must be an eWeLink command with direction open, close, or stop"
                    " or an integer position from 0 to 100"
                )

        fields = set(payload)
        device_type = device.device_type.name
        is_dualr3 = _is_dualr3(device)
        if "ir_data" in fields and (
            brand != "broadlink" or fields != {"ir_data"} or device_type != "IR_REMOTE"
        ):
            raise web.HTTPBadRequest(text="ir_data is supported only by Broadlink IR remotes")
        if brand == "ewelink":
            uiid = _ewelink_uiid(device)
            color_fields = fields & {"hue", "saturation", "color_temp"}
            if is_dualr3 and "cover" not in fields and fields != {"on", "channel"}:
                raise web.HTTPBadRequest(
                    text="DUALR3 relay control requires an explicit channel and on state"
                )
            if "cover" in fields:
                state = self._adapter(device).get_cached_state(device_id)
                params = state.raw.get("params") if state is not None else None
                if not is_dualr3 or not isinstance(params, dict) or params.get("workMode") != 2:
                    raise web.HTTPConflict(
                        text="DUALR3 cover commands require confirmed motor mode"
                    )
                if "position" in payload["cover"] and cover_calibrated(params) is not True:
                    raise web.HTTPConflict(
                        text="DUALR3 position commands require a calibrated motor"
                    )
            if "on" in fields and device_type not in {
                "ON_OFF_PLUG", "ON_OFF_LIGHT", "DIMMABLE_LIGHT", "COLOR_LIGHT", "THERMOSTAT",
            }:
                raise web.HTTPBadRequest(text=f"on is unsupported for eWeLink {device_type} devices")
            if "brightness" in fields and device_type not in {"DIMMABLE_LIGHT", "COLOR_LIGHT"}:
                raise web.HTTPBadRequest(text="brightness is supported only for eWeLink dimmers")
            if "brightness" in fields and payload["brightness"] == 0 and payload.get("on") is True:
                raise web.HTTPBadRequest(text="brightness 0 conflicts with on=true")
            if (payload.get("on") is False and payload.get("brightness", 0) > 0):
                raise web.HTTPBadRequest(text="brightness above 0 conflicts with on=false")
            if color_fields and (
                uiid not in {22, 59}
                or device_type != "COLOR_LIGHT"
                or ("hue" in color_fields) != ("saturation" in color_fields)
                or ("color_temp" in color_fields and len(color_fields) != 1)
            ):
                raise web.HTTPBadRequest(
                    text="Color commands require a supported eWeLink B1 or L1 light"
                )
            if "color_temp" in color_fields and uiid != 22:
                raise web.HTTPBadRequest(
                    text="Color temperature commands are supported only for eWeLink B1"
                )
            if color_fields and payload.get("on") is False:
                raise web.HTTPBadRequest(text="Color commands cannot be combined with on=false")
            if color_fields and payload.get("brightness") == 0:
                raise web.HTTPBadRequest(text="Color commands cannot use brightness 0")
            if "channel" in fields:
                if fields != {"on", "channel"}:
                    raise web.HTTPBadRequest(text="channel can only be combined with on")
                adapter = self._adapter(device)
                if not is_dualr3:
                    state = adapter.get_cached_state(device_id)
                    switches = state.raw.get("switches") if state is not None else None
                    if not isinstance(switches, list) or not any(
                        isinstance(item, dict) and item.get("outlet") == payload["channel"]
                        for item in switches
                    ):
                        raise web.HTTPBadRequest(
                            text="channel is not present in the latest eWeLink state"
                        )
        elif brand == "xiaomi":
            if fields != {"on"} or device_type not in {"ON_OFF_PLUG", "ON_OFF_LIGHT"}:
                raise web.HTTPBadRequest(text="Xiaomi miIO devices support only on/off commands")
        elif brand == "broadlink":
            is_virtual_ir = device.raw_metadata.get("virtual_ir") is True
            if is_virtual_ir or device_type == "ON_OFF_PLUG":
                if fields != {"on"}:
                    raise web.HTTPBadRequest(text="This Broadlink endpoint supports only on/off")
            elif device_type == "IR_REMOTE":
                raise web.HTTPBadRequest(text="Send ir_data to a Broadlink IR remote")
            else:
                raise web.HTTPBadRequest(
                    text=f"Commands are unsupported for Broadlink {device_type} devices"
                )
        elif brand == "onvif":
            if device_type != "CAMERA" or fields != {"ptz"}:
                raise web.HTTPBadRequest(text="ONVIF cameras currently support PTZ commands only")
            adapter = self._adapter(device)
            if (not isinstance(adapter, OnvifAdapter)
                    or not adapter.has_credentials(device_id)
                    or device.raw_metadata.get("onvif_authenticated") is not True):
                raise web.HTTPConflict(text="Configure valid local ONVIF credentials first")
            if not adapter.supports_ptz(device_id):
                raise web.HTTPConflict(text="This ONVIF camera has no discovered PTZ profile")
        try:
            adapter = self._adapter(device)
            success = await adapter.set_state(device_id, **payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            await self._refresh_state(self._adapter(device), device_id)
            logger.warning("Command failed for %s:%s", brand, device_id, exc_info=True)
            raise web.HTTPBadGateway(text="LAN command failed") from None
        if not success:
            await self._refresh_state(adapter, device_id)
            if is_dualr3:
                state = adapter.get_cached_state(device_id)
                params = state.raw.get("params") if state is not None else None
                expected_mode = 2 if "cover" in fields else 1
                if not isinstance(params, dict) or params.get("workMode") != expected_mode:
                    mode_name = "motor" if expected_mode == 2 else "relay"
                    raise web.HTTPConflict(
                        text=f"DUALR3 control requires confirmed {mode_name} mode"
                    )
                if "cover" in fields:
                    if "position" in payload["cover"] and cover_calibrated(params) is not True:
                        raise web.HTTPConflict(
                            text="DUALR3 position commands require a calibrated motor"
                        )
                    raise web.HTTPBadGateway(text="DUALR3 motor command was not confirmed")
                switches = state.raw.get("switches")
                if not isinstance(switches, list) or not any(
                    isinstance(item, dict) and item.get("outlet") == payload["channel"]
                    for item in switches
                ):
                    raise web.HTTPBadRequest(
                        text="channel is not present in the latest DUALR3 state"
                    )
            raise web.HTTPBadGateway(text="Device did not confirm the command")
        await self._refresh_state(adapter, device_id)
        return web.json_response({"ok": True, "device_id": device_id})

    async def get_matter_pairing(self, request: web.Request) -> web.Response:
        """Return Matter pairing codes to loopback clients while unpaired."""
        self._check_loopback_origin(request)
        if self.matter_pairing is None:
            raise web.HTTPNotFound(text="Matter is disabled")
        return web.json_response(
            self.matter_pairing(), headers={"Cache-Control": "no-store"},
        )

    async def dashboard(self, request: web.Request) -> web.Response:
        """Serve the local control panel from the same-origin API."""
        page = Path(__file__).resolve().parent.parent / "web" / "index.html"
        if not page.is_file():
            raise web.HTTPNotFound(text="Dashboard is not installed")
        return web.FileResponse(page, headers={"Cache-Control": "no-store"})

    async def learn_ir(self, request: web.Request) -> web.Response:
        self._check_command_origin(request)
        brand, device_id = request.match_info["brand"], request.match_info["device_id"]
        device = self._device(brand, device_id)
        if device is None:
            raise web.HTTPNotFound(text="Unknown device")
        if brand != "broadlink" or device.device_type.name != "IR_REMOTE":
            raise web.HTTPBadRequest(text="IR learning is only available on Broadlink IR remotes")
        adapter = self._adapter(device)
        learn = getattr(adapter, "learn_ir", None)
        if learn is None:
            raise web.HTTPNotImplemented(text="This Broadlink adapter has no IR learning support")
        try:
            code = await learn(device_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("IR learning failed for %s", device_id, exc_info=True)
            raise web.HTTPBadGateway(text="Broadlink IR learning failed") from None
        if not code:
            raise web.HTTPBadGateway(text="No IR code was captured")
        return web.json_response({"device_id": device_id, "ir_data": code.hex()})

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self._runner is not None:
                raise RuntimeError("Local API server is already running")
            if self._camera_media._stopping:
                self._camera_media = CameraMedia(self._camera_runtime_path)
            app = web.Application(client_max_size=1024 * 1024)
            app.add_routes([
                web.get("/", self.dashboard),
                web.get("/dashboard", self.dashboard),
                web.get("/health", self.health),
                web.get("/api/matter/pairing", self.get_matter_pairing),
                web.get("/api/devices", self.list_devices),
                web.get("/api/integrations/yoosee", self.yoosee_status),
                web.post("/api/integrations/yoosee/login", self.yoosee_login),
                web.get("/api/integrations/yoosee/devices", self.yoosee_devices),
                web.delete("/api/integrations/yoosee", self.yoosee_logout),
                web.post("/api/devices/onvif/{device_id}/sessions", self.create_camera_session),
                web.post("/api/camera-sessions/{session_id}/ice", self.camera_ice),
                web.post("/api/camera-sessions/{session_id}/answer", self.camera_answer),
                web.get("/api/camera-sessions/{session_id}", self.camera_session_status),
                web.delete("/api/camera-sessions/{session_id}", self.close_camera_session),
                web.get("/api/devices/{brand}/{device_id}", self.get_state),
                web.get(
                    "/api/devices/{brand}/{device_id}/snapshot",
                    self.get_camera_snapshot,
                ),
                web.get(
                    "/api/devices/eseecloud/{device_id}/stream",
                    self.get_eseecloud_stream,
                ),
                web.get(
                    "/api/devices/eseecloud/{device_id}/stream-info",
                    self.get_eseecloud_stream_info,
                ),
                web.put("/api/devices/{brand}/{device_id}/state", self.set_state),
                web.post("/api/devices/{brand}/{device_id}/learn-ir", self.learn_ir),
            ])
            runner = web.AppRunner(app, access_log=logger)
            self._runner = runner
            try:
                await runner.setup()
                site = web.TCPSite(runner, self.host, self.port)
                await site.start()
            except BaseException:
                try:
                    await runner.cleanup()
                except Exception:
                    logger.exception("Failed to clean up partially started Local API")
                finally:
                    if self._runner is runner:
                        self._runner = None
                raise
            logger.info("Local API listening at http://%s:%d", self.host, self.port)

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            await self._camera_media.stop()
            runner = self._runner
            if runner is None:
                return
            try:
                await runner.cleanup()
            finally:
                if self._runner is runner:
                    self._runner = None
