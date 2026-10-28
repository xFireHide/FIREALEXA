"""Tests for eWeLink LAN response validation without network dependencies."""

from __future__ import annotations

import unittest

from matter_bridge.adapters.ewelink_protocol import parse_state_response, successful_response


class EwelinkProtocolTests(unittest.TestCase):
    def test_success_requires_numeric_zero_error(self) -> None:
        self.assertTrue(successful_response({"error": 0}))
        for response in (
            None,
            [],
            {"error": True},
            {"error": "0"},
            {"error": 1},
            {},
        ):
            with self.subTest(response=response):
                self.assertFalse(successful_response(response))

    def test_parses_single_switch_dimmer_and_th_sensor_readings(self) -> None:
        response = {"error": 0, "data": {
            "switch": "on",
            "brightness": 120,
            "params": {"currentTemperature": "23.75", "currentHumidity": 48},
        }}

        state = parse_state_response(response)

        self.assertTrue(state.online)
        self.assertTrue(state.on)
        self.assertEqual(state.brightness, 100)
        self.assertEqual(state.temperature, 23.75)
        self.assertEqual(state.humidity, 48.0)

    def test_filters_invalid_multichannel_rows_without_mutating_response(self) -> None:
        switches = [
            {"outlet": 0, "switch": "off"},
            {"outlet": 1, "switch": "on"},
            {"outlet": True, "switch": "on"},
            {"outlet": 32, "switch": "on"},
            {"outlet": 2, "switch": "unknown"},
            "malformed",
        ]
        response = {"error": 0, "data": {"switches": switches}}

        state = parse_state_response(response)

        self.assertTrue(state.online)
        self.assertTrue(state.on)
        self.assertEqual(state.raw["switches"], switches[:2])
        self.assertEqual(response["data"]["switches"], switches)

    def test_does_not_publish_boolean_or_nonfinite_sensor_values(self) -> None:
        state = parse_state_response({"error": 0, "data": {
            "switch": "off",
            "brightness": True,
            "params": {
                "currentTemperature": True,
                "currentHumidity": "Infinity",
                "currentPressure": 10**1000,
            },
        }})

        self.assertTrue(state.online)
        self.assertFalse(state.on)
        self.assertIsNone(state.brightness)
        self.assertIsNone(state.temperature)
        self.assertIsNone(state.humidity)

    def test_ignores_integer_sensor_values_outside_float_range(self) -> None:
        state = parse_state_response({"error": 0, "data": {
            "params": {"currentTemperature": 10**1000},
        }})

        self.assertTrue(state.online)
        self.assertIsNone(state.temperature)

    def test_rejects_success_envelope_with_invalid_data(self) -> None:
        for response in (
            {"error": 0},
            {"error": 0, "data": None},
            {"error": 1, "data": {"switch": "on"}},
        ):
            with self.subTest(response=response):
                self.assertFalse(parse_state_response(response).online)


if __name__ == "__main__":
    unittest.main()
