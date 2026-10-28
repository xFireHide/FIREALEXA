"""
eWeLink / Sonoff LAN crypto utilities.

Protocol: AES-128-CBC
Key derivation: MD5(apikey)
IV: random 16 bytes, sent base64-encoded in the request
Padding: PKCS7
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


def derive_key(apikey: str) -> bytes:
    """Derive AES-128 key from device apikey via MD5."""
    return hashlib.md5(apikey.encode("utf-8")).digest()


def encrypt_payload(plaintext: str, apikey: str, iv: bytes | None = None) -> tuple[str, str]:
    """
    Encrypt a JSON payload for eWeLink LAN API.
    
    Returns:
        (encrypted_data_b64, iv_b64)
    """
    key = derive_key(apikey)
    if iv is None:
        iv = os.urandom(16)
    if len(iv) != 16:
        raise ValueError("eWeLink AES-CBC IV must be exactly 16 bytes")

    padder = PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()


def decrypt_payload(ciphertext_b64: str, apikey: str, iv_b64: str) -> str:
    """
    Decrypt an eWeLink LAN response payload.
    
    Returns:
        Decrypted JSON string.
    """
    if not isinstance(ciphertext_b64, str) or not isinstance(iv_b64, str):
        raise ValueError("eWeLink response ciphertext and IV must be base64 strings")
    key = derive_key(apikey)
    try:
        iv = base64.b64decode(iv_b64, validate=True)
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("eWeLink response contains invalid base64") from exc
    if len(iv) != 16:
        raise ValueError("eWeLink response IV must be exactly 16 bytes")
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("eWeLink ciphertext must contain complete AES blocks")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode("utf-8")
