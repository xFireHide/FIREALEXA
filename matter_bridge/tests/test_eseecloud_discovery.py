"""EseeCloud LAN discovery codec cases.

These assert the reverse-engineered request bytes and response acceptance rules
transcribed from the Android app. Synthetic datagrams are not hardware evidence.
"""

import unittest

from matter_bridge.adapters.eseecloud_discovery import (
    DEFAULT_PORT,
    MULTICAST_ADDR,
    NVR_PORT,
    REQUEST_SEARCH_DEVICE,
    build_common_discovery_request,
    build_legacy_nvr_request,
    build_new_nvr_request,
    parse_common_response,
    parse_new_nvr_response,
)


class ConstantTests(unittest.TestCase):
    def test_transport_constants_match_app(self):
        self.assertEqual(NVR_PORT, 9013)
        self.assertEqual(DEFAULT_PORT, 12306)
        self.assertEqual(MULTICAST_ADDR, "224.2.3.4")
        self.assertEqual(REQUEST_SEARCH_DEVICE, 134489421)


class RequestBuildingTests(unittest.TestCase):
    def test_common_request_is_byte_exact(self):
        self.assertEqual(
            build_common_discovery_request(REQUEST_SEARCH_DEVICE),
            b'{"fromApp":true,"requestID":134489421,'
            b'"tokenID":"1473433878","command":"discovery"}',
        )

    def test_new_nvr_request_is_byte_exact(self):
        self.assertEqual(
            build_new_nvr_request(2),
            b"SEARCH * HDS/1.1\r\nCSeq:2\r\n"
            b"Client-ID:CeCOlDpmTuzViBQDgbrPgFkfnyyzNabc\r\n"
            b"Accept-Type:text/HDP\r\nContent-Length:13\r\n"
            b"X-Search-Type:NVR\r\n"
            b'{"Ver":"1.1"}',
        )

    def test_legacy_request_variants(self):
        self.assertEqual(build_legacy_nvr_request(), b"SEARCHDEV")
        self.assertEqual(build_legacy_nvr_request(""), b"SEARCHDEV")
        self.assertEqual(build_legacy_nvr_request("ABC123"), b"SEARCHJAABC123&")

    def test_requests_reject_invalid_arguments(self):
        with self.assertRaises(ValueError):
            build_common_discovery_request(-1)
        with self.assertRaises(TypeError):
            build_new_nvr_request(True)
        with self.assertRaises(ValueError):
            build_legacy_nvr_request("bad&serial")
        with self.assertRaises(ValueError):
            build_legacy_nvr_request("x" * 65)


class NvrResponseParsingTests(unittest.TestCase):
    def _payload(self) -> bytes:
        return (
            b"garbage-prefix "
            b'{"Esee-ID":"EE12345","Device-ID":"dev-1","Device-Model":"NVR-8",'
            b'"Device-Type":"NVR","Channel-Cnt":8,"Software-Version":"1.2.3",'
            b'"Nonce":"abcd","Ver":"1.1",'
            b'"Capabilities":{"Http-Port":8080,"MaxHardDiskDrivers":2},'
            b'"Wired":[{"IP":"192.168.1.9","MAC":"aa:bb","Connected":true}]}'
        )

    def test_parses_full_new_nvr_response(self):
        result = parse_new_nvr_response(self._payload())
        assert result is not None
        self.assertEqual(result.esee_id, "EE12345")
        self.assertEqual(result.device_id, "dev-1")
        self.assertEqual(result.device_model, "NVR-8")
        self.assertEqual(result.channel_count, 8)
        self.assertEqual(result.http_port, 8080)
        self.assertEqual(len(result.wired), 1)

    def test_rejects_response_without_esee_id(self):
        self.assertIsNone(parse_new_nvr_response(b'{"Device-ID":"dev-1"}'))
        self.assertIsNone(parse_new_nvr_response(b'{"Esee-ID":""}'))

    def test_rejects_non_object_and_oversized(self):
        self.assertIsNone(parse_new_nvr_response(b"not json at all"))
        self.assertIsNone(parse_new_nvr_response(b"[1,2,3]"))
        self.assertIsNone(parse_new_nvr_response(b'{"Esee-ID":"x"}' + b" " * 70_000))

    def test_tolerates_wrong_field_types(self):
        result = parse_new_nvr_response(
            b'{"Esee-ID":"E1","Channel-Cnt":"eight","Capabilities":42}'
        )
        assert result is not None
        self.assertEqual(result.channel_count, 0)
        self.assertEqual(result.http_port, 0)


class CommonResponseParsingTests(unittest.TestCase):
    def test_accepts_matching_request_id(self):
        payload = (
            b'{"fromApp":false,"requestID":134489421,"deviceID":"CAM-1",'
            b'"UID":"TUTK-UID","version":"0.4",'
            b'"devinfo":{"deviceType":"IPC","enableChannel":1,"maxChannel":1}}'
        )
        result = parse_common_response(payload)
        assert result is not None
        self.assertEqual(result.device_id, "CAM-1")
        self.assertEqual(result.uid, "TUTK-UID")
        self.assertEqual(result.device_type, "IPC")

    def test_rejects_app_echo_and_foreign_request_id(self):
        # fromApp == true is the app's own broadcast looping back.
        self.assertIsNone(parse_common_response(
            b'{"fromApp":true,"requestID":134489421,"deviceID":"CAM-1"}'
        ))
        self.assertIsNone(parse_common_response(
            b'{"fromApp":false,"requestID":999,"deviceID":"CAM-1"}'
        ))
        self.assertIsNone(parse_common_response(
            b'{"fromApp":false,"requestID":134489421,"deviceID":""}'
        ))


if __name__ == "__main__":
    unittest.main()
