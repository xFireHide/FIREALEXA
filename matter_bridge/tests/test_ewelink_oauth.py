"""Tests for the eWeLink OAuth 2.0 import request/response logic."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest
from urllib.parse import parse_qs, urlsplit

from matter_bridge.adapters.ewelink_oauth import (
    EwelinkDevice,
    build_authorize_url,
    clean_name,
    create_nonce,
    device_list_headers,
    host_for_region,
    merge_apikeys,
    parse_device_list,
    parse_token_response,
    token_request,
)

APP_ID = "app-123"
APP_SECRET = "s3cr3t"


def hmac_b64(message: bytes) -> str:
    return base64.b64encode(
        hmac.new(APP_SECRET.encode(), message, hashlib.sha256).digest()
    ).decode()


class OAuthSigningTests(unittest.TestCase):
    def test_authorize_url_signs_appid_seq(self) -> None:
        url = build_authorize_url(
            APP_ID, APP_SECRET, "http://127.0.0.1:8766/callback", "xyz",
            seq=1700000000000, nonce="abcd1234",
        )
        parts = urlsplit(url)
        self.assertEqual(f"{parts.scheme}://{parts.netloc}{parts.path}",
                         "https://c2ccdn.coolkit.cc/oauth/index.html")
        q = parse_qs(parts.query)
        self.assertEqual(q["clientId"], [APP_ID])
        self.assertEqual(q["seq"], ["1700000000000"])
        self.assertEqual(q["grantType"], ["authorization_code"])
        self.assertEqual(q["state"], ["xyz"])
        self.assertEqual(q["authorization"], [hmac_b64(b"app-123_1700000000000")])

    def test_token_request_signs_exact_body(self) -> None:
        body, headers = token_request(
            APP_ID, APP_SECRET, "the-code", "http://127.0.0.1:8766/callback", nonce="n0nce123",
        )
        self.assertEqual(json.loads(body), {
            "grantType": "authorization_code", "code": "the-code",
            "redirectUrl": "http://127.0.0.1:8766/callback",
        })
        self.assertEqual(headers["Authorization"], "Sign " + hmac_b64(body))
        self.assertEqual(headers["X-CK-Appid"], APP_ID)
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_device_list_headers_use_bearer_token(self) -> None:
        headers = device_list_headers(APP_ID, "tok", nonce="n0nce123")
        self.assertEqual(headers["Authorization"], "Bearer tok")
        self.assertEqual(headers["X-CK-Appid"], APP_ID)

    def test_create_nonce_shape(self) -> None:
        nonce = create_nonce()
        self.assertEqual(len(nonce), 8)
        self.assertTrue(nonce.isalnum() and nonce.isascii())

    def test_host_for_region(self) -> None:
        self.assertEqual(host_for_region("us"), "https://us-apia.coolkit.cc")
        self.assertEqual(host_for_region("eu"), "https://eu-apia.coolkit.cc")
        self.assertEqual(host_for_region("as"), "https://as-apia.coolkit.cc")
        self.assertEqual(host_for_region("cn"), "https://cn-apia.coolkit.cn")
        for bad in ("", "US", "xx", "../", "u"):
            with self.assertRaises(ValueError):
                host_for_region(bad)


class OAuthResponseTests(unittest.TestCase):
    def test_parse_token_response(self) -> None:
        self.assertEqual(
            parse_token_response({"error": 0, "data": {"accessToken": "abc"}}), "abc"
        )

    def test_parse_token_response_rejects_errors_and_missing(self) -> None:
        for payload in (
            {"error": 403, "msg": "denied", "data": {}},
            {"error": 0, "data": {}},
            {"data": {"accessToken": ""}},
            [], "nope",
        ):
            with self.assertRaises(ValueError):
                parse_token_response(payload)

    def test_parse_device_list_extracts_key_and_skips_invalid(self) -> None:
        payload = {"error": 0, "data": {"thingList": [
            {"itemData": {"deviceid": "1000abcd", "devicekey": "k1",
                          "name": "Lamp", "extra": {"uiid": 1}}},
            {"itemData": {"deviceid": "1000efgh", "devicekey": "k2"}},  # no name/uiid
            {"itemData": {"deviceid": "1000abcd", "devicekey": "dup"}},  # duplicate id
            {"itemData": {"deviceid": "bad id!", "devicekey": "k"}},     # bad id
            {"itemData": {"deviceid": "1000zzzz"}},                      # no key
            {"note": "not a device"},
        ]}}
        devices = parse_device_list(payload)
        self.assertEqual(devices, [
            EwelinkDevice("1000abcd", "k1", "Lamp", 1),
            EwelinkDevice("1000efgh", "k2", "1000efgh", None),
        ])

    def test_parse_device_list_requires_thinglist(self) -> None:
        with self.assertRaises(ValueError):
            parse_device_list({"error": 0, "data": {}})


class MergeApikeysTests(unittest.TestCase):
    def test_merge_preserves_other_fields_and_counts(self) -> None:
        config = {"api_port": 8765, "ewelink_apikeys": {"old": "keep", "chg": "before"}}
        devices = [
            EwelinkDevice("new", "k-new", "New", 1),
            EwelinkDevice("chg", "after", "Changed", 2),
            EwelinkDevice("old", "keep", "Same", 3),
        ]
        merged, added, updated = merge_apikeys(config, devices)
        self.assertEqual(merged["api_port"], 8765)
        self.assertEqual(merged["ewelink_apikeys"],
                         {"old": "keep", "chg": "after", "new": "k-new"})
        self.assertEqual((added, updated), (1, 1))
        self.assertEqual(merged["ewelink_names"],
                         {"new": "New", "chg": "Changed", "old": "Same"})
        # The original config is not mutated.
        self.assertEqual(config["ewelink_apikeys"], {"old": "keep", "chg": "before"})

    def test_merge_skips_fallback_names_and_keeps_existing(self) -> None:
        config = {"ewelink_names": {"other": "Kitchen"}}
        merged, _, _ = merge_apikeys(config, [EwelinkDevice("a", "k", "a", None)])
        self.assertEqual(merged["ewelink_names"], {"other": "Kitchen"})

    def test_clean_name(self) -> None:
        self.assertEqual(clean_name("  Luz\nSala\x00 "), "LuzSala")
        self.assertEqual(clean_name("Lâmpada do Quarto"), "Lâmpada do Quarto")
        self.assertEqual(clean_name("x" * 300), "x" * 128)
        for bad in ("", "  ", "\n", None, 5):
            self.assertIsNone(clean_name(bad))

    def test_merge_into_config_without_existing_keys(self) -> None:
        merged, added, updated = merge_apikeys({}, [EwelinkDevice("a", "k", "A", None)])
        self.assertEqual(merged["ewelink_apikeys"], {"a": "k"})
        self.assertEqual((added, updated), (1, 0))


if __name__ == "__main__":
    unittest.main()
