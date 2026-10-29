"""Tests for exposing Matter pairing codes from the matter.js output."""

from __future__ import annotations

import unittest

from matter_bridge.core.matter_bridge import MatterJsProvider


def provider() -> MatterJsProvider:
    return MatterJsProvider("http://127.0.0.1:8765", "node", 5540, 95577132, 3562)


class MatterPairingInfoTests(unittest.TestCase):
    def test_unknown_before_output(self) -> None:
        info = provider().pairing_info()
        self.assertIsNone(info["commissioned"])
        self.assertIsNone(info["manual_pairing_code"])

    def test_captures_codes_while_uncommissioned(self) -> None:
        matter = provider()
        matter._note_pairing_output(
            "QR Code URL: https://project-chip.github.io/connectedhomeip/qrcode.html"
            "?data=MT:Y.K90Q1212XYAB6S020"
        )
        matter._note_pairing_output("Manual pairing code: 32564458338")
        info = matter.pairing_info()
        self.assertIs(info["commissioned"], False)
        self.assertEqual(info["manual_pairing_code"], "32564458338")
        self.assertEqual(info["qr_payload"], "MT:Y.K90Q1212XYAB6S020")

    def test_hides_codes_once_commissioned(self) -> None:
        matter = provider()
        matter._note_pairing_output("Manual pairing code: 32564458338")
        matter._note_pairing_output(
            "Matter bridge is commissioned; waiting for controllers to connect."
        )
        info = matter.pairing_info()
        self.assertIs(info["commissioned"], True)
        self.assertIsNone(info["manual_pairing_code"])
        self.assertIsNone(info["qr_payload"])


if __name__ == "__main__":
    unittest.main()
