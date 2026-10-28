"""Pure response normalization for the eWeLink LAN protocol."""

from __future__ import annotations

import math
import colorsys
from typing import Any

from matter_bridge.core.base_adapter import DeviceState


def finite_number(value: Any) -> float | None:
    """Parse a numeric sensor value without accepting booleans or infinities."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = float(value)
        except (OverflowError, ValueError):
            return None
    if not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def successful_response(response: Any) -> bool:
    """Accept only the protocol's numeric zero success code, not JSON booleans."""
    return (
        isinstance(response, dict)
        and isinstance(response.get("error"), int)
        and not isinstance(response["error"], bool)
        and response["error"] == 0
    )


def parse_state_response(response: Any) -> DeviceState:
    """Normalize an eWeLink ``info`` reply into the bridge's state model."""
    if not successful_response(response):
        return DeviceState(online=False)
    data = response.get("data")
    if not isinstance(data, dict):
        return DeviceState(online=False)

    switch = data.get("switch")
    state = DeviceState(
        online=True,
        on=True if switch == "on" else False if switch == "off" else None,
        raw=dict(data),
    )

    switches = data.get("switches")
    if isinstance(switches, list):
        switches = [
            item for item in switches
            if isinstance(item, dict)
            and isinstance(item.get("outlet"), int)
            and not isinstance(item.get("outlet"), bool)
            and 0 <= item["outlet"] <= 31
            and item.get("switch") in {"on", "off"}
        ]
        state.raw["switches"] = switches
        if switches and state.on is None:
            state.on = any(item.get("switch") == "on" for item in switches)

    params = data.get("params")
    observed = {**data, **params} if isinstance(params, dict) else data
    brightness = observed.get("brightness", observed.get("bright"))
    if isinstance(brightness, int) and not isinstance(brightness, bool):
        state.brightness = max(0, min(100, brightness))
    elif all(
        isinstance(observed.get(key), (int, str))
        and not isinstance(observed.get(key), bool)
        for key in ("channel0", "channel1")
    ):
        try:
            channels = [int(observed[key]) for key in ("channel0", "channel1")]
        except (TypeError, ValueError, OverflowError):
            channels = []
        if channels and all(0 <= channel <= 255 for channel in channels):
            state.brightness = max(0, min(100, round((max(channels) - 25) * 100 / 230)))

    if isinstance(params, dict):
        state.temperature = finite_number(params.get("currentTemperature"))
        state.humidity = finite_number(params.get("currentHumidity"))
        position = finite_number(params.get("currLocation"))
        if position is not None and 0 <= position <= 100:
            state.cover_position = round(position)
        motor_turn = params.get("motorTurn")
        if isinstance(motor_turn, str) and motor_turn.isascii() and motor_turn.isdecimal():
            motor_turn = int(motor_turn)
        if type(motor_turn) is int:
            state.cover_motion = {0: "stopped", 1: "opening", 2: "closing"}.get(motor_turn)

    def rgb_values(keys: tuple[str, str, str]) -> tuple[int, int, int] | None:
        values: list[int] = []
        for key in keys:
            value = observed.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                return None
            try:
                channel = int(value)
            except (TypeError, ValueError, OverflowError):
                return None
            if not 0 <= channel <= 255:
                return None
            values.append(channel)
        return values[0], values[1], values[2]

    mode = observed.get("zyx_mode")
    if isinstance(mode, bool):
        mode = None
    if isinstance(mode, str) and mode.isascii() and mode.isdecimal():
        mode = int(mode)
    rgb = (rgb_values(("channel2", "channel3", "channel4")) if mode != 1 else None)
    if rgb is None:
        rgb = rgb_values(("colorR", "colorG", "colorB"))
    if rgb is not None:
        hue, saturation, _ = colorsys.rgb_to_hsv(*(channel / 255 for channel in rgb))
        state.hue = round(hue * 360) % 360
        state.saturation = round(saturation * 100)
        if state.brightness is None:
            state.brightness = round(max(rgb) * 100 / 255)

    if mode == 1:
        white_channels = rgb_values(("channel0", "channel1", "channel2"))
        if white_channels is not None and max(white_channels) > 0 and white_channels[2] == 0:
            cold, warm, _ = white_channels
            kelvin = 6500 if warm == 0 else 4250 if cold == warm else 2000 if cold == 0 else None
            if kelvin is not None:
                state.color_temp = round(1_000_000 / kelvin)

    return state
