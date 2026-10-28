"""Framing regression cases; synthetic bytes are not hardware evidence."""

import unittest

from matter_bridge.adapters.eseecloud_protocol import (
    EseeCloudMediaReader, EseeCloudProtocolError, MAX_FRAME_BYTES,
)


class FragmentedReader:
    def __init__(self, data, chunk_size):
        self.data = data
        self.chunk_size = chunk_size

    async def read(self, size):
        size = min(size, self.chunk_size)
        result, self.data = self.data[:size], self.data[size:]
        return result


PREAMBLE = b"m=video 96 H264/90000\r\n\r\n"


def frame(payload):
    return b"$\x00\x00\x00" + len(payload).to_bytes(4, "big") + payload


class EseeCloudFramingTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragmentation_and_coalescing_preserve_all_bytes(self):
        frames = [frame(b"first"), frame(b"second")]
        for chunk_size in (1, 3, 256):
            with self.subTest(chunk_size=chunk_size):
                media = EseeCloudMediaReader(FragmentedReader(
                    PREAMBLE + b"".join(frames), chunk_size
                ))
                self.assertEqual(await media.read_preamble(), PREAMBLE)
                self.assertEqual([item async for item in media.frames()], frames)
                self.assertEqual(media.media_tracks[0]["codec"], "H264")

    async def test_invalid_headers_and_truncation_are_rejected(self):
        for data in (
            b"$", frame(b"payload")[:-1],
            b"!\x00\x00\x00\x00\x00\x00\x01x",
            frame(b""),
            b"$\x00\x00\x00" + (MAX_FRAME_BYTES + 1).to_bytes(4, "big"),
        ):
            with self.subTest(data=data):
                media = EseeCloudMediaReader(FragmentedReader(PREAMBLE + data, 256))
                await media.read_preamble()
                with self.assertRaises(EseeCloudProtocolError):
                    await anext(media.frames())

    async def test_missing_video_and_unbounded_preamble_are_rejected(self):
        for data in (b"", b"x" * 1024, b"m=audio 8 G711/8000\r\n\r\n"):
            with self.subTest(length=len(data)):
                media = EseeCloudMediaReader(FragmentedReader(data, 256))
                with self.assertRaises(EseeCloudProtocolError):
                    await media.read_preamble()
