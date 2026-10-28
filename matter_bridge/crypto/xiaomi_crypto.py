"""
Xiaomi miIO LAN crypto utilities.

Protocol: AES-128-CBC
Key: MD5(token)
IV: MD5(key + token)
Padding: PKCS7
Token: 16-byte device identity, obtained from Mi Home DB or uninitialized device
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# Magic bytes for miIO packet header
MAGIC = 0x2131

# 32-byte Hello packet: magic(2) + length(2) + 0xFFFFFFFF(4) * 7
HELLO_PACKET = (
    struct.pack(">HH", MAGIC, 0x0020)
    + b"\xff" * 28
)


def derive_key_iv(token: bytes) -> tuple[bytes, bytes]:
    """
    Derive AES key and IV from the device token.
    
    key = MD5(token)
    iv  = MD5(key + token)
    """
    key = hashlib.md5(token).digest()
    iv = hashlib.md5(key + token).digest()
    return key, iv


def encrypt_payload(plaintext: bytes, token: bytes) -> bytes:
    """Encrypt a miIO JSON-RPC payload."""
    key, iv = derive_key_iv(token)

    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_payload(ciphertext: bytes, token: bytes) -> bytes:
    """Decrypt a miIO response payload."""
    key, iv = derive_key_iv(token)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def build_packet(
    token: bytes,
    device_id: int,
    payload: bytes,
    stamp: int | None = None,
) -> bytes:
    """
    Build a complete miIO packet.
    
    Header (32 bytes):
        0x00-0x01: magic (0x2131)
        0x02-0x03: packet length (header + encrypted payload)
        0x04-0x07: unknown (0x00000000)
        0x08-0x0B: device_id
        0x0C-0x0F: stamp (seconds since device boot)
        0x10-0x1F: MD5 checksum of entire packet with token in checksum field
    """
    if stamp is None:
        stamp = int(time.time())

    encrypted = encrypt_payload(payload, token)
    total_len = 32 + len(encrypted)

    # Build header without checksum
    header = bytearray(32)
    struct.pack_into(">HH", header, 0, MAGIC, total_len)
    struct.pack_into(">I", header, 4, 0x00000000)
    struct.pack_into(">I", header, 8, device_id)
    struct.pack_into(">I", header, 12, stamp)
    # Place token in checksum field for MD5 calculation
    header[16:32] = token

    # Calculate MD5 of header (with token) + encrypted payload
    packet_for_hash = bytes(header) + encrypted
    checksum = hashlib.md5(packet_for_hash).digest()

    # Replace token with actual checksum
    header[16:32] = checksum

    return bytes(header) + encrypted


def parse_response(data: bytes, token: bytes) -> tuple[int, int, bytes]:
    """
    Parse a miIO response packet.
    
    Returns:
        (device_id, stamp, decrypted_payload)
    """
    if len(data) < 32:
        raise ValueError(f"Packet too short: {len(data)} bytes")

    magic, length = struct.unpack_from(">HH", data, 0)
    if magic != MAGIC:
        raise ValueError(f"Invalid magic: 0x{magic:04X}")
    if length != len(data):
        raise ValueError(f"Invalid packet length: header={length}, actual={len(data)}")

    device_id = struct.unpack_from(">I", data, 8)[0]
    stamp = struct.unpack_from(">I", data, 12)[0]

    if length == 32:
        # Hello response — no payload, token might be in checksum field
        return device_id, stamp, data[16:32]  # return token/checksum bytes

    encrypted_payload = data[32:]
    if not encrypted_payload or len(encrypted_payload) % 16:
        raise ValueError("Invalid encrypted payload length")
    header = bytearray(data[:32])
    received_checksum = bytes(header[16:32])
    header[16:32] = token
    expected_checksum = hashlib.md5(bytes(header) + encrypted_payload).digest()
    if not hmac.compare_digest(received_checksum, expected_checksum):
        raise ValueError("Invalid miIO packet checksum")
    decrypted = decrypt_payload(encrypted_payload, token)

    return device_id, stamp, decrypted


def parse_hello_response(data: bytes) -> tuple[int, int, bytes]:
    """
    Parse a Hello response to extract device_id, stamp, and token.
    
    The token is in bytes 16-31. If the device has been cloud-configured,
    the token may be zeroed out (all 0xFF or 0x00).
    """
    if len(data) != 32:
        raise ValueError(f"Hello response too short: {len(data)} bytes")

    magic, length = struct.unpack_from(">HH", data, 0)
    if magic != MAGIC or length != 32:
        raise ValueError("Invalid miIO hello response header")

    device_id = struct.unpack_from(">I", data, 8)[0]
    stamp = struct.unpack_from(">I", data, 12)[0]
    token = data[16:32]

    return device_id, stamp, token
