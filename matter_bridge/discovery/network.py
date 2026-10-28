"""IPv4 interface helpers shared by LAN broadcast discovery protocols."""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct

logger = logging.getLogger(__name__)


def get_local_ipv4() -> str:
    """Select the IPv4 source address chosen by the system default route."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
    except OSError:
        return "0.0.0.0"


def is_lan_unicast_address(value: str) -> bool:
    """Accept private or link-local unicast targets, never local/system endpoints."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        (address.is_private or address.is_link_local)
        and not address.is_loopback
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


def get_ipv4_broadcast_interfaces() -> list[tuple[str, str]]:
    """Return active interface/broadcast pairs, with a routed-IP fallback."""
    try:
        import fcntl
    except ImportError:
        return [(get_local_ipv4(), "255.255.255.255")]

    interfaces: list[tuple[str, str]] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            for _, name in socket.if_nameindex():
                request = struct.pack("256s", name.encode()[:15])
                try:
                    flags = struct.unpack_from(
                        "H", fcntl.ioctl(probe.fileno(), 0x8913, request), 16
                    )[0]
                    if flags & 0x1 == 0 or flags & 0x2 == 0 or flags & 0x8:
                        continue
                    address_data = fcntl.ioctl(probe.fileno(), 0x8915, request)
                    netmask_data = fcntl.ioctl(probe.fileno(), 0x891B, request)
                    local_ip = socket.inet_ntoa(address_data[20:24])
                    netmask = socket.inet_ntoa(netmask_data[20:24])
                    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                    address = ipaddress.IPv4Address(local_ip)
                    if network.prefixlen >= 31 or address.is_loopback or address.is_unspecified:
                        continue
                    interfaces.append((local_ip, str(network.broadcast_address)))
                except (OSError, ValueError, struct.error):
                    logger.debug("Skipping unavailable IPv4 interface %s", name, exc_info=True)
    except OSError:
        logger.debug("Could not enumerate IPv4 broadcast interfaces", exc_info=True)

    if interfaces:
        return interfaces
    return [(get_local_ipv4(), "255.255.255.255")]
