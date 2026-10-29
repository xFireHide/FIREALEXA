import { spawn } from "node:child_process";
import { isIP } from "node:net";

const MAX_INPUT = 8 * 1024 * 1024;
const MAX_OUTPUT = 256 * 1024;
export const SNAPSHOT_FORMAT = Object.freeze({ width: 640, height: 360, frameRate: 1, quality: 75 });

// Inspect the JPEG frame header before invoking a decoder. This is a dimension
// bound, not full JPEG validation; FFmpeg still validates the encoded image.
export function jpegResolution(data) {
  if (!Buffer.isBuffer(data) || data.length < 4 || data.length > MAX_INPUT ||
      data.readUInt16BE(0) !== 0xffd8 || data.readUInt16BE(data.length - 2) !== 0xffd9) {
    throw new Error("Invalid snapshot JPEG");
  }
  let offset = 2;
  while (offset < data.length - 2) {
    if (data[offset++] !== 0xff) break;
    while (data[offset] === 0xff) offset++;
    const marker = data[offset++];
    if (marker === 0xda || marker === 0xd9) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > data.length) break;
    const size = data.readUInt16BE(offset);
    if (size < 2 || offset + size > data.length) break;
    if ([0xc0, 0xc1, 0xc2].includes(marker)) {
      if (size < 8 || data[offset + 2] !== 8) break;
      const height = data.readUInt16BE(offset + 3);
      const width = data.readUInt16BE(offset + 5);
      if (!width || !height || width > 8192 || height > 8192 || width * height > 16_777_216) break;
      return { width, height };
    }
    offset += size;
  }
  throw new Error("Unsupported or oversized snapshot dimensions");
}

export async function resizeSnapshot(input, quality = SNAPSHOT_FORMAT.quality, executable = "ffmpeg") {
  jpegResolution(input);
  if (!Number.isInteger(quality) || quality < 1 || quality > 100) throw new Error("Invalid JPEG quality");
  const { width, height } = SNAPSHOT_FORMAT;
  const quantizer = String(Math.round(31 - (quality - 1) * 29 / 99));
  return new Promise((resolve, reject) => {
    const child = spawn(executable, ["-nostdin", "-hide_banner", "-loglevel", "error",
      "-max_alloc", "67108864", "-protocol_whitelist", "pipe", "-f", "image2pipe",
      "-c:v", "mjpeg", "-threads", "1", "-i", "pipe:0", "-frames:v", "1", "-an",
      "-vf", `scale=${width}:${height}:force_original_aspect_ratio=decrease,pad=${width}:${height}:(ow-iw)/2:(oh-ih)/2`,
      "-c:v", "mjpeg", "-threads", "1", "-q:v", quantizer, "-f", "image2pipe", "pipe:1"],
    { stdio: ["pipe", "pipe", "ignore"], shell: false });
    const chunks = [];
    let size = 0;
    let failure = false;
    const timer = setTimeout(() => { failure = true; child.kill("SIGKILL"); }, 10_000);
    child.stdin.on("error", () => { /* EPIPE is handled by process exit. */ });
    child.stdout.on("data", chunk => {
      size += chunk.length;
      if (size > MAX_OUTPUT) { failure = true; child.kill("SIGKILL"); }
      else chunks.push(chunk);
    });
    child.once("error", () => {
      clearTimeout(timer);
      reject(new Error("Snapshot encoder could not start"));
    });
    child.once("close", code => {
      clearTimeout(timer);
      try {
        if (code !== 0 || failure) throw new Error();
        const data = Buffer.concat(chunks);
        const resolution = jpegResolution(data);
        if (resolution.width !== width || resolution.height !== height) throw new Error();
        resolve({ data, resolution });
      } catch { reject(new Error("Snapshot conversion failed")); }
    });
    child.stdin.end(input);
  });
}

export function createOnvifSnapshotCapture(apiUrl, deviceId, profile, { fetchImpl = fetch } = {}) {
  const base = new URL(apiUrl);
  if (base.protocol !== "http:" || base.username || base.password ||
      !(base.hostname === "localhost" || base.hostname === "[::1]" ||
        (isIP(base.hostname) === 4 && base.hostname.startsWith("127.")))) {
    throw new Error("Snapshot backend must use loopback HTTP");
  }
  const url = new URL(`/api/devices/onvif/${encodeURIComponent(deviceId)}/snapshot`, base);
  url.searchParams.set("profile", profile);
  return async quality => {
    const response = await fetchImpl(url, { redirect: "error", signal: AbortSignal.timeout(10_000) });
    if (!response.ok || !response.body) {
      await response.body?.cancel();
      throw new Error("Snapshot backend failed");
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > MAX_INPUT) throw new Error("Snapshot exceeds size limit");
      chunks.push(Buffer.from(chunk));
    }
    return resizeSnapshot(Buffer.concat(chunks), quality);
  };
}
