"""Brand-specific LAN protocol adapters."""

from importlib import import_module

__all__ = [
    "BroadlinkAdapter", "EseeCloudAdapter", "EwelinkAdapter", "OnvifAdapter", "XiaomiAdapter",
]

_MODULES = {
    "BroadlinkAdapter": "broadlink_adapter",
    "EseeCloudAdapter": "eseecloud_adapter",
    "EwelinkAdapter": "ewelink_adapter",
    "OnvifAdapter": "onvif_adapter",
    "XiaomiAdapter": "xiaomi_adapter",
}


def __getattr__(name: str):
    """Keep pure protocol parsers independent of network/crypto dependencies."""
    module_name = _MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    adapter = getattr(import_module(f"{__name__}.{module_name}"), name)
    globals()[name] = adapter
    return adapter
