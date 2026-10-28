"""Bounded reader for the EseeCloud HTTP media framing documented by go2rtc."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator


MAX_PREAMBLE_BYTES = 1024
MAX_FRAME_BYTES = 4 * 1024 * 1024
_MEDIA_LINE = re.compile(rb"m=(video|audio) (\d+) (\w+)/(\d+)\S*")


class EseeCloudProtocolError(ValueError):
    """The configured camera returned bytes outside the supported framing."""


class EseeCloudMediaReader:
    """Incrementally validate and yield the EseeCloud media preamble and frames."""

    def __init__(self, reader) -> None:
        self._reader = reader
        self._buffer = bytearray()
        self.media_tracks: tuple[dict[str, int | str], ...] = ()

    async def read_preamble(self) -> bytes:
        """Read codec metadata through CRLF-CRLF, bounded to go2rtc's probe size."""
        terminator = b"\r\n\r\n"
        while True:
            end = self._buffer.find(terminator)
            if end >= 0:
                end += len(terminator)
                if end > MAX_PREAMBLE_BYTES:
                    raise EseeCloudProtocolError("EseeCloud preamble is too large")
                preamble = bytes(self._buffer[:end])
                del self._buffer[:end]
                self._validate_preamble(preamble)
                return preamble
            if len(self._buffer) >= MAX_PREAMBLE_BYTES:
                raise EseeCloudProtocolError("EseeCloud preamble has no terminator")
            chunk = await self._reader.read(
                min(256, MAX_PREAMBLE_BYTES - len(self._buffer))
            )
            if not chunk:
                raise EseeCloudProtocolError("EseeCloud stream ended before its preamble")
            self._buffer.extend(chunk)

    def _validate_preamble(self, preamble: bytes) -> None:
        tracks: list[dict[str, int | str]] = []
        for media, payload_type, codec, clock_rate in _MEDIA_LINE.findall(preamble):
            if media not in {b"video", b"audio"}:
                continue
            try:
                payload = int(payload_type)
                clock = int(clock_rate)
            except ValueError:
                continue
            supported = (media == b"video" and codec in {b"H264", b"H265"}) or (
                media == b"audio" and codec == b"G711"
            )
            if supported and 0 <= payload <= 127 and 1 <= clock <= 1_000_000:
                tracks.append({
                    "media": media.decode("ascii"),
                    "payload_type": payload,
                    "codec": codec.decode("ascii"),
                    "clock_rate": clock,
                })
        if not any(track["media"] == "video" for track in tracks):
            raise EseeCloudProtocolError("EseeCloud preamble has no supported video codec")
        self.media_tracks = tuple(tracks[:4])

    async def frames(self) -> AsyncIterator[bytes]:
        """Yield one validated frame at a time, without buffering the whole stream."""
        while True:
            header = await self._read_exactly(8, allow_clean_eof=True)
            if header is None:
                return
            if header[0] != ord("$"):
                raise EseeCloudProtocolError("EseeCloud frame has an invalid start byte")
            size = int.from_bytes(header[4:8], "big")
            if not 1 <= size <= MAX_FRAME_BYTES:
                raise EseeCloudProtocolError("EseeCloud frame length is outside the allowed range")
            payload = await self._read_exactly(size)
            assert payload is not None
            yield header + payload

    async def _read_exactly(self, size: int, *, allow_clean_eof: bool = False) -> bytes | None:
        while len(self._buffer) < size:
            chunk = await self._reader.read(min(64 * 1024, size - len(self._buffer)))
            if not chunk:
                if allow_clean_eof and not self._buffer:
                    return None
                raise EseeCloudProtocolError("EseeCloud stream ended in the middle of a frame")
            self._buffer.extend(chunk)
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result

