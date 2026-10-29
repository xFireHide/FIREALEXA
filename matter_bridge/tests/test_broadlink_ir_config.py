"""Tests for adding learned Broadlink IR mappings to config.json."""

from __future__ import annotations

import unittest

from matter_bridge.adapters.broadlink_adapter import BroadlinkAdapter
from matter_bridge.adapters.broadlink_ir_config import add_mapping, slugify, unique_id

REMOTE = "aa:bb:cc:dd:ee:ff:2737"


class BroadlinkIrConfigTests(unittest.TestCase):
    def test_slugify(self) -> None:
        self.assertEqual(slugify("TV da Sala"), "tv-da-sala")
        self.assertEqual(slugify("Ar-condicionado Quarto Nº2"), "ar-condicionado-quarto-no2")
        self.assertEqual(slugify("Lâmpada"), "lampada")
        self.assertEqual(slugify("!!!"), "aparelho")

    def test_unique_id(self) -> None:
        self.assertEqual(unique_id("tv", set()), "tv")
        self.assertEqual(unique_id("tv", {"tv", "tv-2"}), "tv-3")

    def test_add_mapping_preserves_config_and_existing_entries(self) -> None:
        config = {
            "api_port": 8765,
            "broadlink_ir_mappings": {
                REMOTE: [{"id": "tv-da-sala", "name": "TV da Sala", "on": "aa", "off": "bb"}],
            },
        }
        merged, mapping_id = add_mapping(config, REMOTE, "TV da Sala", "ABCD", "00ff")
        self.assertEqual(mapping_id, "tv-da-sala-2")
        self.assertEqual(merged["api_port"], 8765)
        entries = merged["broadlink_ir_mappings"][REMOTE]
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[1], {
            "id": "tv-da-sala-2", "name": "TV da Sala", "on": "abcd", "off": "00ff",
        })
        # The input config is not mutated.
        self.assertEqual(len(config["broadlink_ir_mappings"][REMOTE]), 1)

    def test_add_mapping_rejects_bad_input(self) -> None:
        for name, on, off in (("", "aa", "bb"), ("TV", "zz", "bb"), ("TV", "", "bb"),
                              ("TV", "aa", "a" * 8194), ("\n", "aa", "bb")):
            with self.assertRaises(ValueError):
                add_mapping({}, REMOTE, name, on, off)

    def test_written_mappings_load_in_adapter(self) -> None:
        merged, _ = add_mapping({}, REMOTE, "Ar do Quarto", "0102", "0304")
        merged, _ = add_mapping(merged, REMOTE, "TV", "0506", "0506")
        BroadlinkAdapter(merged["broadlink_ir_mappings"])  # raises if the format is wrong


if __name__ == "__main__":
    unittest.main()
