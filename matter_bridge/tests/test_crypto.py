"""Protocol crypto regression tests (run when the runtime crypto dependency is installed)."""

from __future__ import annotations

import importlib.util
import unittest


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "cryptography is not installed")
class CryptoRoundTripTests(unittest.TestCase):
    def test_broadlink_aes_round_trip_and_zero_padding(self) -> None:
        from matter_bridge.crypto.broadlink_crypto import decrypt, encrypt

        plaintext = b"\x01\x02\x03"
        ciphertext = encrypt(plaintext)
        self.assertEqual(len(ciphertext) % 16, 0)
        self.assertEqual(decrypt(ciphertext)[:len(plaintext)], plaintext)

    def test_ewelink_payload_round_trip_with_fixed_iv(self) -> None:
        from matter_bridge.crypto.ewelink_crypto import decrypt_payload, encrypt_payload

        plaintext = '{"switch":"on"}'
        ciphertext, iv = encrypt_payload(plaintext, "local-api-key", b"0123456789abcdef")
        self.assertEqual(decrypt_payload(ciphertext, "local-api-key", iv), plaintext)

    def test_xiaomi_packet_round_trip_and_checksum_validation(self) -> None:
        from matter_bridge.crypto.xiaomi_crypto import build_packet, parse_response

        token = bytes(range(16))
        packet = build_packet(token, device_id=0x12345678, payload=b'{"id":1}', stamp=42)
        self.assertEqual(parse_response(packet, token), (0x12345678, 42, b'{"id":1}'))

        damaged = bytearray(packet)
        damaged[-1] ^= 0x01
        with self.assertRaisesRegex(ValueError, "checksum"):
            parse_response(bytes(damaged), token)


if __name__ == "__main__":
    unittest.main()
