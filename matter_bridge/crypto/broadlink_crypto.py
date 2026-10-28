"""
Broadlink LAN crypto utilities.

Protocol: AES-128-CBC
Default key (pre-auth): 0x09762... (16 bytes)
Default IV: 0x562e... (16 bytes)
Post-auth: device returns a new session key
Padding: Zero-padded to 16-byte boundary
Checksum: Sum of all bytes & 0xFFFF at header offset 0x20
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Default key used before authentication
DEFAULT_KEY = bytes([
    0x09, 0x76, 0x28, 0x34, 0x3F, 0xE9, 0x9E, 0x23,
    0x76, 0x5C, 0x15, 0x13, 0xAC, 0xCF, 0x8B, 0x02,
])

# Default IV
DEFAULT_IV = bytes([
    0x56, 0x2E, 0x17, 0x99, 0x6D, 0x09, 0x3D, 0x28,
    0xDD, 0xB3, 0xBA, 0x69, 0x5A, 0x2E, 0x6F, 0x58,
])


def encrypt(payload: bytes, key: bytes = DEFAULT_KEY, iv: bytes = DEFAULT_IV) -> bytes:
    """Encrypt payload with AES-128-CBC. Zero-pads to 16-byte boundary."""
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("Broadlink AES key and IV must each be 16 bytes")
    # Pad to 16-byte boundary
    pad_len = (16 - len(payload) % 16) % 16
    if pad_len:
        payload = payload + b"\x00" * pad_len

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(payload) + encryptor.finalize()


def decrypt(ciphertext: bytes, key: bytes = DEFAULT_KEY, iv: bytes = DEFAULT_IV) -> bytes:
    """Decrypt AES-128-CBC ciphertext."""
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("Broadlink AES key and IV must each be 16 bytes")
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("Broadlink ciphertext must contain complete AES blocks")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def checksum(packet: bytes) -> int:
    """Broadlink packet checksum: sum of all bytes & 0xFFFF."""
    return sum(packet) & 0xFFFF


def build_header(
    devtype: int,
    command: int,
    count: int,
    mac: bytes,
    device_id: int = 0,
    payload_len: int = 0,
) -> bytearray:
    """
    Build a 56-byte (0x38) Broadlink packet header.
    
    Header layout:
        0x00-0x03: magic (5aa5aa55 5aa5aa55 — varies by command)
        0x24-0x25: devtype
        0x26-0x27: command
        0x28-0x29: count (packet counter)
        0x2A-0x2F: mac (6 bytes, reversed)
        0x30-0x33: device_id
        0x34-0x35: checksum placeholder (calculated after)
    """
    header = bytearray(0x38)
    header[0x00:0x08] = b"\x5a\xa5\xaa\x55\x5a\xa5\xaa\x55"

    # Device type
    struct.pack_into("<H", header, 0x24, devtype)
    # Command
    struct.pack_into("<H", header, 0x26, command)
    # Counter
    struct.pack_into("<H", header, 0x28, count)
    # MAC (reversed byte order)
    mac_bytes = mac[:6] if len(mac) >= 6 else mac + b"\x00" * (6 - len(mac))
    header[0x2A:0x30] = mac_bytes[::-1]
    # Device ID
    struct.pack_into("<I", header, 0x30, device_id)

    return header


def finalize_packet(
    header: bytearray, encrypted_payload: bytes, plaintext_payload: bytes
) -> bytes:
    """
    Combine header + encrypted payload, then set checksums.
    
    Offset 0x34 checksums the plaintext payload; offset 0x20 checksums the full
    packet including ciphertext and the payload checksum.
    """
    packet = bytearray(header + encrypted_payload)
    struct.pack_into("<H", packet, 0x34, (0xBEAF + sum(plaintext_payload)) & 0xFFFF)
    struct.pack_into(
        "<H", packet, 0x20,
        (0xBEAF + sum(packet[:0x20]) + sum(packet[0x22:])) & 0xFFFF,
    )
    return bytes(packet)


def validate_response(packet: bytes) -> None:
    """Validate the Broadlink packet checksum and firmware error field."""
    if len(packet) < 0x38:
        raise ValueError(f"Broadlink response too short: {len(packet)} bytes")
    received = int.from_bytes(packet[0x20:0x22], "little")
    expected = (0xBEAF + sum(packet[:0x20]) + sum(packet[0x22:])) & 0xFFFF
    if received != expected:
        raise ValueError(
            f"Broadlink checksum mismatch: got 0x{received:04x}, expected 0x{expected:04x}"
        )
    error = int.from_bytes(packet[0x22:0x24], "little")
    if error:
        raise ValueError(f"Broadlink device returned error 0x{error:04x}")


def parse_auth_response(response: bytes, key: bytes = DEFAULT_KEY) -> tuple[int, bytes]:
    """
    Parse authentication response to extract device_id and session key.
    
    Returns:
        (device_id, new_aes_key)
    """
    validate_response(response)
    encrypted_payload = response[0x38:]
    if len(encrypted_payload) < 0x20 or len(encrypted_payload) % 16:
        raise ValueError("Broadlink auth response payload is incomplete")
    decrypted = decrypt(encrypted_payload, key)
    if len(decrypted) < 0x14:
        raise ValueError("Broadlink auth response must contain a device ID and session key")

    # Device ID at offset 0x00 (4 bytes LE)
    device_id = struct.unpack_from("<I", decrypted, 0x00)[0]
    # New AES key at offset 0x04 (16 bytes)
    new_key = decrypted[0x04:0x14]

    return device_id, new_key
