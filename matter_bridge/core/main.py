"""Application entry point for the Matter bridge."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import ipaddress
import re
import secrets
import signal
import uuid
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Sequence

from matter_bridge.adapters.broadlink_adapter import BroadlinkAdapter
from matter_bridge.adapters.ewelink_adapter import EwelinkAdapter
from matter_bridge.adapters.eseecloud_adapter import EseeCloudAdapter
from matter_bridge.adapters.onvif_adapter import OnvifAdapter
from matter_bridge.adapters.xiaomi_adapter import XiaomiAdapter
from matter_bridge.core.base_adapter import BaseAdapter, DeviceInfo
from matter_bridge.core.registry import DeviceRegistry
from matter_bridge.core.storage import write_private_json
from matter_bridge.core.matter_bridge import MatterJsProvider
from matter_bridge.core.api import LocalAPI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local LAN Matter bridge")
    parser.add_argument("--config", type=Path, default=Path("matter-bridge.json"),
                        help="device registry path (secrets read from sibling config.json)")
    parser.add_argument("--log-level", default="INFO")
    return parser


def _valid_setup_passcode(value: int) -> bool:
    text = f"{value:08d}"
    return (
        1 <= value <= 99_999_998
        and value not in {20_202_021, 12_345_678, 87_654_321}
        and len(set(text)) > 1
    )


def _save_config(path: Path, config: dict[str, object]) -> None:
    write_private_json(path, config)


def _load_config(path: Path) -> dict[str, object]:
    if path.is_symlink():
        raise RuntimeError(f"Config path must not be a symlink: {path}")
    if not path.exists():
        return {}
    if not path.is_file():
        raise RuntimeError(f"Config path must be a regular file: {path}")
    try:
        os.chmod(path, 0o600)
    except OSError:
        logging.warning("Could not restrict configuration permissions at %s", path)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Invalid config file {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise RuntimeError(f"Invalid config file {path}: root value must be a JSON object")
    return loaded


def _make_matter_provider(
    config: dict[str, object], config_file: Path, api_host: str, api_port: int
) -> MatterJsProvider | None:
    settings = config.get("matter", {})
    if not isinstance(settings, dict):
        raise ValueError("config.json matter must be an object")
    unknown = set(settings) - {
        "enabled", "passcode", "discriminator", "node_id", "port", "vendor_id",
        "product_id",
    }
    if unknown:
        fields = ", ".join(sorted(unknown))
        raise ValueError(f"Unsupported config.json matter fields: {fields}")
    enabled = settings.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("config.json matter.enabled must be boolean")
    if not enabled:
        return None

    passcode = settings.get("passcode")
    if passcode is None:
        while True:
            candidate = secrets.randbelow(90_000_000) + 10_000_000
            if _valid_setup_passcode(candidate):
                passcode = candidate
                break
        settings["passcode"] = passcode
    if (not isinstance(passcode, int) or isinstance(passcode, bool)
            or not _valid_setup_passcode(passcode)):
        raise ValueError("matter.passcode must be a valid 8-digit Matter setup passcode")

    discriminator = settings.get("discriminator")
    if discriminator is None:
        discriminator = secrets.randbelow(4096)
        settings["discriminator"] = discriminator
    if (not isinstance(discriminator, int) or isinstance(discriminator, bool)
            or not 0 <= discriminator <= 4095):
        raise ValueError("matter.discriminator must be an integer from 0 to 4095")

    node_id = settings.get("node_id")
    if node_id is None:
        node_id = f"firealexa-{uuid.uuid4().hex[:12]}"
        settings["node_id"] = node_id
    if not isinstance(node_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,32}", node_id) is None:
        raise ValueError("matter.node_id must be 1-32 ASCII letters, digits, '_' or '-'")

    matter_port = settings.get("port", 5540)
    vendor_id = settings.get("vendor_id", 0xFFF1)
    product_id = settings.get("product_id", 0x8000)
    for key, value, low, high in (
        ("port", matter_port, 1, 65535),
        ("vendor_id", vendor_id, 0, 65535),
        ("product_id", product_id, 0, 65535),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise ValueError(f"matter.{key} must be an integer from {low} to {high}")
    settings.update(port=matter_port, vendor_id=vendor_id, product_id=product_id)
    config["matter"] = settings
    _save_config(config_file, config)

    if vendor_id == 0xFFF1:
        logging.warning(
            "Matter is using the development VID 0xFFF1; commissioning with "
            "Apple Home or Google Home is not guaranteed"
        )

    connect_host = api_host
    if api_host in {"0.0.0.0", "::"}:
        connect_host = "127.0.0.1"
    try:
        if ipaddress.ip_address(connect_host).version == 6:
            connect_host = f"[{connect_host}]"
    except ValueError:
        pass
    return MatterJsProvider(
        api_url=f"http://{connect_host}:{api_port}",
        node_id=node_id,
        port=matter_port,
        passcode=passcode,
        discriminator=discriminator,
        vendor_id=vendor_id,
        product_id=product_id,
        storage_path=config_file.parent / "matter-storage",
    )


async def run(config_path: Path, discover: bool = True) -> None:
    """Start adapters, perform configured discovery and wait for shutdown."""
    config_file = config_path.with_name("config.json")
    config = _load_config(config_file)
    unknown = set(config) - {
        "ewelink_apikeys", "xiaomi_tokens", "broadlink_ir_mappings",
        "onvif_credentials", "eseecloud_streams", "api_host", "api_port",
        "allow_remote_commands", "matter",
    }
    if unknown:
        fields = ", ".join(sorted(unknown))
        raise ValueError(f"Unsupported config.json fields: {fields}")
    apikeys = config.get("ewelink_apikeys", {})
    if not isinstance(apikeys, dict) or not all(
        isinstance(key, str) and bool(key.strip())
        and isinstance(value, str) and bool(value)
        for key, value in apikeys.items()
    ):
        raise ValueError(
            "config.json ewelink_apikeys must map non-empty device IDs to non-empty keys"
        )
    xiaomi_tokens = config.get("xiaomi_tokens", {})
    if not isinstance(xiaomi_tokens, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in xiaomi_tokens.items()
    ):
        raise ValueError("config.json xiaomi_tokens must map miIO device IDs to hex tokens")
    broadlink_ir_mappings = config.get("broadlink_ir_mappings", {})
    if not isinstance(broadlink_ir_mappings, dict):
        raise ValueError("config.json broadlink_ir_mappings must be an object")
    onvif_credentials = config.get("onvif_credentials", {})
    if not isinstance(onvif_credentials, dict):
        raise ValueError("config.json onvif_credentials must map device IDs to credentials")
    for device_id, credentials in onvif_credentials.items():
        if (not isinstance(device_id, str) or not device_id
                or not isinstance(credentials, dict)
                or set(credentials) != {"username", "password"}):
            raise ValueError(
                "config.json onvif_credentials entries must contain username and password"
            )
        for field in ("username", "password"):
            value = credentials[field]
            if (not isinstance(value, str) or not value or len(value) > 256
                    or any(ord(character) < 0x20 and character not in "\t\r\n"
                           for character in value)):
                raise ValueError(
                    f"config.json onvif_credentials[{device_id!r}].{field} is invalid"
                )
    eseecloud_streams = config.get("eseecloud_streams", {})
    if not isinstance(eseecloud_streams, dict):
        raise ValueError("config.json eseecloud_streams must map camera IDs to LAN stream settings")
    api_host = config.get("api_host", "127.0.0.1")
    api_port = config.get("api_port", 8765)
    allow_remote = config.get("allow_remote_commands", False)
    if not isinstance(api_host, str) or not api_host:
        raise ValueError("config.json api_host must be a non-empty string")
    if not isinstance(api_port, int) or isinstance(api_port, bool) or not 1 <= api_port <= 65535:
        raise ValueError("config.json api_port must be an integer from 1 to 65535")
    if not isinstance(allow_remote, bool):
        raise ValueError("config.json allow_remote_commands must be a boolean")
    adapters = [
        EwelinkAdapter(apikeys),
        BroadlinkAdapter(broadlink_ir_mappings),
        XiaomiAdapter(xiaomi_tokens),
        OnvifAdapter(onvif_credentials),
        EseeCloudAdapter(eseecloud_streams),
    ]
    matter = _make_matter_provider(config, config_file, api_host, api_port)
    registry = DeviceRegistry(config_path)
    adapters_by_brand = {adapter.BRAND: adapter for adapter in adapters}
    for stored_device in registry.all_devices():
        adapter = adapters_by_brand.get(stored_device.brand)
        load_device = getattr(adapter, "load_device", None) if adapter else None
        if load_device:
            try:
                load_device(stored_device)
            except (TypeError, ValueError, OverflowError) as exc:
                logging.warning(
                    "Discarding invalid stored %s device %s: %s",
                    stored_device.brand, stored_device.device_id, exc,
                )
                registry.unregister(stored_device.brand, stored_device.device_id)
    api = LocalAPI(
        registry,
        adapters,
        host=api_host,
        port=api_port,
        allow_remote_commands=allow_remote,
        matter_status=lambda: matter.status if matter is not None else "disabled",
        camera_runtime_path=config_file.parent / "matter-storage" / "runtime",
    )
    stop_event = asyncio.Event()
    matter_task: asyncio.Task[None] | None = None
    discovery_tasks: list[asyncio.Task[None]] = []
    retry_discovery_soon: set[str] = set()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        for adapter in adapters:
            await adapter.start()
        await api.start()
        if matter is not None:
            matter_task = asyncio.create_task(_supervise_matter(matter, stop_event))
        if discover:
            results = await asyncio.gather(
                *(adapter.discover() for adapter in adapters), return_exceptions=True
            )
            for adapter, result in zip(adapters, results):
                if isinstance(result, BaseException):
                    logging.error("Discovery failed for %s: %s", adapter.BRAND, result)
                    retry_discovery_soon.add(adapter.BRAND)
                    continue
                if not result:
                    retry_discovery_soon.add(adapter.BRAND)
                for device in result:
                    should_authenticate = (
                        device.brand == "broadlink"
                        or device.brand == "eseecloud"
                        or (device.brand == "xiaomi" and bool(device.auth_token))
                        or (device.brand == "ewelink" and device.device_id in apikeys)
                        or (isinstance(adapter, OnvifAdapter)
                            and adapter.has_credentials(device.device_id))
                    )
                    if should_authenticate:
                        await _authenticate_safely(adapter, device)
                    try:
                        registry.register(device)
                    except (TypeError, ValueError) as exc:
                        logging.warning(
                            "Skipping invalid %s discovery record %s: %s",
                            device.brand, device.device_id, exc,
                        )
                        continue
                    logging.info(
                        "Found %s device %s at %s",
                        device.brand,
                        device.device_id,
                        device.ip,
                    )
        for device in registry.all_devices():
            adapter = adapters_by_brand.get(device.brand)
            if adapter is not None:
                await _publish_device_state(adapter, device.device_id)
        for adapter in adapters:
            discovery_tasks.append(asyncio.create_task(
                _periodic_discovery(
                    adapter,
                    registry,
                    stop_event,
                    initial_delay=5.0 if adapter.BRAND in retry_discovery_soon else 60.0,
                )
            ))
        await stop_event.wait()
    finally:
        async def cleanup_runtime() -> None:
            for task in discovery_tasks:
                task.cancel()
            if discovery_tasks:
                await asyncio.gather(*discovery_tasks, return_exceptions=True)
            if matter_task:
                matter_task.cancel()
                await asyncio.gather(matter_task, return_exceptions=True)

            async def stop_component(
                name: str, stop_operation: Callable[[], Awaitable[None]],
            ) -> None:
                try:
                    await stop_operation()
                except asyncio.CancelledError:
                    logging.error("Shutdown of %s was cancelled", name)
                except Exception:
                    logging.exception("Shutdown of %s failed", name)

            if matter is not None:
                await stop_component("Matter.js", matter.stop)
            await stop_component("Local API", api.stop)
            results = await asyncio.gather(
                *(adapter.stop() for adapter in reversed(adapters)),
                return_exceptions=True,
            )
            for adapter, result in zip(reversed(adapters), results):
                if isinstance(result, BaseException):
                    logging.error("Shutdown of %s adapter failed: %s", adapter.BRAND, result)

        cleanup_task = asyncio.create_task(cleanup_runtime(), name="bridge-shutdown")
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            # Let resource cleanup finish before propagating cancellation of run().
            try:
                await asyncio.shield(cleanup_task)
            finally:
                raise


async def _supervise_matter(provider: MatterJsProvider, stop_event: asyncio.Event) -> None:
    delay = 2.0
    last_failure: str | None = None
    while not stop_event.is_set():
        failure: str | None = None
        try:
            await provider.start()
        except Exception as exc:
            provider.mark_unavailable()
            failure = f"Could not start Matter.js bridge: {exc}"
        else:
            started_at = asyncio.get_running_loop().time()
            try:
                code = await provider.wait()
            except Exception as exc:
                failure = f"Matter.js process monitor failed: {exc}"
                try:
                    await provider.stop()
                except Exception:
                    logging.exception("Could not stop Matter.js after monitor failure")
                provider.mark_unavailable()
            else:
                if stop_event.is_set():
                    return
                failure = f"Matter.js bridge exited with code {code}"
                provider.mark_unavailable()
                if asyncio.get_running_loop().time() - started_at >= 60.0:
                    delay = 2.0
                    last_failure = None

        if failure is not None and failure != last_failure:
            logging.error("%s", failure)
        last_failure = failure or last_failure

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=delay)
            return
        except asyncio.TimeoutError:
            delay = min(delay * 2, 60.0)


async def _authenticate_safely(
    adapter: BaseAdapter,
    device: DeviceInfo,
    *,
    force: bool = False,
) -> bool:
    """Keep a transient device auth failure isolated to that device."""
    try:
        if isinstance(adapter, BroadlinkAdapter):
            authenticated = await adapter.authenticate(device, force=force)
        else:
            authenticated = await adapter.authenticate(device)
    except asyncio.CancelledError:
        raise
    except Exception:
        logging.exception("Authentication raised for %s device %s",
                          device.brand, device.device_id)
        return False
    if not authenticated:
        logging.warning("Authentication failed for %s device %s",
                        device.brand, device.device_id)
    return authenticated


async def _publish_device_state(
    adapter: BaseAdapter,
    device_id: str,
) -> None:
    """Publish an immediate state sample without aborting other devices."""
    try:
        await adapter.publish_state(device_id, await adapter.get_state(device_id))
    except asyncio.CancelledError:
        raise
    except Exception:
        logging.debug("State sample unavailable for %s device %s",
                      adapter.BRAND, device_id, exc_info=True)


async def _periodic_discovery(
    adapter: BaseAdapter,
    registry: DeviceRegistry,
    stop_event: asyncio.Event,
    *,
    initial_delay: float = 60.0,
) -> None:
    delay = max(0.0, initial_delay)
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=delay)
            return
        except asyncio.TimeoutError:
            pass
        try:
            devices = await adapter.discover(timeout=3.0)
            # Empty scans are common on quiet networks. Keep an initial quick
            # retry, then back off instead of probing every five seconds
            # forever when a brand has no devices on this LAN.
            delay = 60.0 if devices else min(max(delay * 2, 5.0), 60.0)
            for device in devices:
                should_authenticate = (
                    isinstance(adapter, BroadlinkAdapter)
                    and not adapter.is_online(device.device_id)
                ) or (
                    adapter.BRAND == "xiaomi"
                    and bool(device.auth_token)
                    and not device.raw_metadata.get("info")
                ) or (
                    isinstance(adapter, OnvifAdapter)
                    and adapter.has_credentials(device.device_id)
                    and not device.raw_metadata.get("onvif_authenticated")
                ) or (
                    isinstance(adapter, EwelinkAdapter)
                    and adapter.has_apikey(device.device_id)
                    and not device.raw_metadata.get("lan_authenticated")
                ) or (
                    isinstance(adapter, EseeCloudAdapter)
                )
                if should_authenticate:
                    await _authenticate_safely(
                        adapter,
                        device,
                        force=isinstance(adapter, BroadlinkAdapter),
                    )
                try:
                    registry.register(device)
                except (TypeError, ValueError) as exc:
                    logging.warning(
                        "Skipping invalid %s discovery record %s: %s",
                        device.brand, device.device_id, exc,
                    )
                    continue
                if isinstance(adapter, EseeCloudAdapter):
                    await adapter.publish_state(
                        device.device_id, await adapter.get_state(device.device_id)
                    )
                elif adapter.get_cached_state(device.device_id) is None:
                    await _publish_device_state(adapter, device.device_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logging.exception("Periodic discovery failed for %s", adapter.BRAND)
            delay = min(max(delay * 2, 5.0), 60.0)


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(run(args.config))


if __name__ == "__main__":
    main()
