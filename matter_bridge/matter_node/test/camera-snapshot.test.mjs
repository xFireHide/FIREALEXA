import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { createOnvifSnapshotCapture, jpegResolution, resizeSnapshot } from "../camera-snapshot.mjs";

function fixture() {
  const result = spawnSync("ffmpeg", ["-hide_banner", "-loglevel", "error", "-f", "lavfi",
    "-i", "color=c=blue:size=1280x720", "-frames:v", "1", "-c:v", "mjpeg",
    "-threads", "1", "-f", "image2pipe", "pipe:1"], { timeout: 10000, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.status, 0, "FFmpeg fixture generation failed");
  return result.stdout;
}

test("snapshot conversion returns a decodable JPEG at the advertised resolution", async () => {
  const input = fixture();
  assert.deepEqual(jpegResolution(input), { width: 1280, height: 720 });
  const result = await resizeSnapshot(input, 75);
  assert.deepEqual(result.resolution, { width: 640, height: 360 });
  // Independently decode/probe the output; do not rely only on our header parser.
  const probe = spawnSync("ffprobe", ["-v", "error", "-show_entries", "stream=width,height",
    "-of", "json", "-i", "pipe:0"], { input: result.data, timeout: 10000 });
  assert.equal(probe.status, 0);
  assert.deepEqual(JSON.parse(probe.stdout).streams[0], { width: 640, height: 360 });
  const decode = spawnSync("ffmpeg", ["-v", "error", "-i", "pipe:0", "-f", "null", "-"],
    { input: result.data, timeout: 10000 });
  assert.equal(decode.status, 0);
});

test("malformed or oversized frames are rejected before decoding", async () => {
  await assert.rejects(resizeSnapshot(Buffer.from("not jpeg")), /Invalid snapshot JPEG/);
  const fake = Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0, 8, 8, 0xff, 0xff, 0xff, 0xff, 3, 0xff, 0xd9]);
  await assert.rejects(resizeSnapshot(fake), /oversized snapshot dimensions/);
  await assert.rejects(resizeSnapshot(fixture(), 101), /quality/);
});

test("snapshot backend URL is loopback-only and encodes profile/device IDs", async () => {
  assert.throws(() => createOnvifSnapshotCapture("http://192.168.1.1", "cam", "main"), /loopback/);
  const capture = createOnvifSnapshotCapture("http://127.0.0.1:8765", "cam/a", "main&other", {
    fetchImpl: async (url, options) => {
      assert.equal(url.pathname, "/api/devices/onvif/cam%2Fa/snapshot");
      assert.equal(url.searchParams.get("profile"), "main&other");
      assert.equal(options.redirect, "error");
      return new Response(fixture(), { headers: { "Content-Type": "image/jpeg" } });
    },
  });
  assert.deepEqual((await capture(75)).resolution, { width: 640, height: 360 });
});
