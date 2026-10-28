"""
Device registry — central store for discovered devices across all adapters.
Handles persistence, deduplication, and lookup.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from matter_bridge.core.base_adapter import DeviceInfo, DeviceType
from matter_bridge.core.storage import write_private_json
from matter_bridge.discovery.network import is_lan_unicast_address

logger = logging.getLogger(__name__)

_DEVICE_TYPE_MAP = {dt.name: dt for dt in DeviceType}
_NON_PERSISTED_METADATA_KEYS = {
    "accesstoken", "apikey", "authtoken", "authorization", "credential",
    "credentials", "devicekey", "devicetoken", "encryptionkey", "key", "localkey",
    "networkkey", "password", "privatekey", "refreshtoken", "secret", "sessionkey",
    "token",
    # ONVIF URLs and profile tokens are bound to the current authenticated
    # session. The adapter reacquires them after discovery on every startup.
    "onvifauthenticated", "onvifprofiles", "onvifservices",
}


def _persistable_metadata(value: Any, depth: int = 0) -> Any:
    """Copy metadata while excluding credentials and transient session caches."""
    if depth > 32:
        return None
    if isinstance(value, dict):
        return {
            key: _persistable_metadata(item, depth + 1)
            for key, item in value.items()
            if isinstance(key, str)
            and key.casefold().replace("-", "").replace("_", "")
            not in _NON_PERSISTED_METADATA_KEYS
            and not key.casefold().replace("-", "").replace("_", "").endswith(
                ("token", "password", "secret", "credential", "apikey", "sessionkey",
                 "privatekey", "encryptionkey", "devicekey", "localkey", "networkkey",
                 "accesskey", "authkey", "aeskey", "signingkey")
            )
        }
    if isinstance(value, list):
        return [_persistable_metadata(item, depth + 1) for item in value]
    if isinstance(value, tuple):
        return [_persistable_metadata(item, depth + 1) for item in value]
    return value


class DeviceRegistry:
    """Device registry with optional atomic JSON persistence."""

    def __init__(self, persist_path: Path | None = None) -> None:
        self._devices: dict[str, DeviceInfo] = {}
        self._persist_path = persist_path
        if persist_path and persist_path.is_symlink():
            raise ValueError(f"Device registry path must not be a symlink: {persist_path}")
        if persist_path and persist_path.exists() and not persist_path.is_file():
            raise ValueError(f"Device registry path must be a regular file: {persist_path}")
        if persist_path and persist_path.exists():
            try:
                os.chmod(persist_path, 0o600)
            except OSError:
                logger.warning("Could not restrict device registry permissions at %s", persist_path)
            self._load()

    def register(self, device: DeviceInfo) -> None:
        """Register or update a device."""
        if not isinstance(device, DeviceInfo):
            raise TypeError("registry accepts DeviceInfo records only")
        for field_name in ("brand", "device_id", "ip"):
            value = getattr(device, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"device {field_name} must be a non-empty string")
        if not is_lan_unicast_address(device.ip):
            raise ValueError("device ip must be a private or link-local unicast address")
        if (not isinstance(device.port, int) or isinstance(device.port, bool)
                or not 1 <= device.port <= 65535):
            raise ValueError("device port must be an integer from 1 to 65535")
        if not isinstance(device.device_type, DeviceType):
            raise ValueError("device_type must be a DeviceType")
        if not isinstance(device.raw_metadata, dict):
            raise ValueError("raw_metadata must be an object")
        if not isinstance(device.auth_token, bytes) or not isinstance(device.session_key, bytes):
            raise ValueError("device authentication material must be bytes")

        key = f"{device.brand}:{device.device_id}"
        existing = self._devices.get(key)
        if existing:
            incoming_model = device.model
            model_unchanged = (
                not incoming_model
                or not existing.model
                or incoming_model == existing.model
            )
            # Merge: keep auth tokens if new device doesn't have them
            if not device.auth_token and existing.auth_token:
                device.auth_token = existing.auth_token
            if not device.session_key and existing.session_key:
                device.session_key = existing.session_key
            # Preserve useful descriptive values when a later scan omits them.
            for attribute in ("mac", "model", "firmware", "name"):
                if not getattr(device, attribute) and getattr(existing, attribute):
                    setattr(device, attribute, getattr(existing, attribute))
            if (device.device_type == DeviceType.UNKNOWN
                    and existing.device_type != DeviceType.UNKNOWN
                    and model_unchanged):
                device.device_type = existing.device_type
            device.raw_metadata = {**existing.raw_metadata, **device.raw_metadata}
        self._devices[key] = device
        logger.debug("Registered device %s at %s:%d", key, device.ip, device.port)
        self._save()

    def unregister(self, brand: str, device_id: str) -> None:
        key = f"{brand}:{device_id}"
        self._devices.pop(key, None)
        self._save()

    def get(self, brand: str, device_id: str) -> DeviceInfo | None:
        return self._devices.get(f"{brand}:{device_id}")

    def get_by_ip(self, ip: str) -> DeviceInfo | None:
        for dev in self._devices.values():
            if dev.ip == ip:
                return dev
        return None

    def all_devices(self) -> list[DeviceInfo]:
        return list(self._devices.values())

    def devices_by_brand(self, brand: str) -> list[DeviceInfo]:
        return [d for d in self._devices.values() if d.brand == brand]

    def _save(self) -> None:
        if not self._persist_path:
            return
        try:
            data = []
            for dev in self._devices.values():
                entry: dict[str, Any] = {
                    "brand": dev.brand,
                    "device_id": dev.device_id,
                    "ip": dev.ip,
                    "port": dev.port,
                    "mac": dev.mac,
                    "model": dev.model,
                    "firmware": dev.firmware,
                    "device_type": dev.device_type.name,
                    "name": dev.name,
                    "raw_metadata": _persistable_metadata(dev.raw_metadata),
                }
                data.append(entry)
            write_private_json(self._persist_path, data)
        except (OSError, TypeError, ValueError):
            logger.exception("Failed to save device registry")

    def _load(self) -> None:
        if not self._persist_path or not self._persist_path.exists():
            return
        try:
            data = json.loads(self._persist_path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError("registry root must be a JSON array")
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            logger.exception("Failed to load device registry")
            return

        invalid_entries = 0
        contains_legacy_secret_fields = False
        for index, entry in enumerate(data):
            try:
                if not isinstance(entry, dict):
                    raise ValueError("entry must be a JSON object")
                brand = entry.get("brand")
                device_id = entry.get("device_id")
                ip = entry.get("ip")
                port = entry.get("port")
                if not all(isinstance(value, str) and value for value in (brand, device_id, ip)):
                    raise ValueError("brand, device_id and ip must be non-empty strings")
                if not is_lan_unicast_address(ip):
                    raise ValueError("ip must be a private or link-local unicast address")
                if (not isinstance(port, int) or isinstance(port, bool)
                        or not 1 <= port <= 65535):
                    raise ValueError("port must be an integer from 1 to 65535")

                text_fields = {}
                for field_name in ("mac", "model", "firmware", "name"):
                    value = entry.get(field_name, "")
                    if not isinstance(value, str):
                        raise ValueError(f"{field_name} must be a string")
                    text_fields[field_name] = value

                raw_metadata = entry.get("raw_metadata", {})
                if not isinstance(raw_metadata, dict):
                    raise ValueError("raw_metadata must be a JSON object")
                persisted_metadata = _persistable_metadata(raw_metadata)
                contains_legacy_secret_fields |= persisted_metadata != raw_metadata
                device_type = entry.get("device_type", "")
                if not isinstance(device_type, str):
                    raise ValueError("device_type must be a string")

                # Older registry versions stored Xiaomi tokens and Broadlink
                # session material in plaintext hex. Credentials now come from
                # config.json or are negotiated again on the LAN.
                contains_legacy_secret_fields |= any(field_name in entry for field_name in (
                    "auth_token", "session_key",
                ))

                dev = DeviceInfo(
                    brand=brand,
                    device_id=device_id,
                    ip=ip,
                    port=port,
                    mac=text_fields["mac"],
                    model=text_fields["model"],
                    firmware=text_fields["firmware"],
                    device_type=_DEVICE_TYPE_MAP.get(
                        device_type, DeviceType.UNKNOWN
                    ),
                    name=text_fields["name"],
                    raw_metadata=persisted_metadata,
                )
                self._devices[f"{dev.brand}:{dev.device_id}"] = dev
            except (TypeError, ValueError, KeyError) as exc:
                invalid_entries += 1
                logger.warning("Skipping invalid device registry entry %d: %s", index, exc)

        logger.info("Loaded %d devices from registry", len(self._devices))
        if invalid_entries:
            logger.warning("Discarded %d invalid device registry entries", invalid_entries)
            self._save()
        elif contains_legacy_secret_fields:
            logger.info("Migrating registry entries to remove persisted authentication material")
            self._save()
