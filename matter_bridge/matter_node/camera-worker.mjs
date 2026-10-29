// Private newline-delimited JSON IPC. Credentials arrive only through stdin.
import { createInterface } from "node:readline";
import { CameraVideoSession, FfmpegRtpSource, rtspInput } from "./camera-video.mjs";

const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 13)) process.exit(1);
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
let session;
let closing = false;
const send = value => process.stdout.write(`${JSON.stringify(value)}\n`);
async function stop() {
  if (closing) return;
  closing = true;
  await session?.close();
  lines.close();
  process.stdin.destroy();
}
for (const signal of ["SIGTERM", "SIGINT"]) process.once(signal, () => { void stop(); });
process.stdin.once("end", () => { void stop(); });
try {
  for await (const line of lines) {
    if (closing) break;
    if (Buffer.byteLength(line) > 128 * 1024) throw new Error("IPC request too large");
    const request = JSON.parse(line);
    if (["offer", "solicit"].includes(request.command) && !session) {
      const source = new FfmpegRtpSource(rtspInput(request.source.uri, request.source.ip));
      session = new CameraVideoSession(source, {
        audio: request.source.audio === true, onClose: () => { void stop(); },
      });
      const sdp = request.command === "solicit" ? await session.offer() : await session.answer(request.sdp);
      send({ ok: true, sdp });
    } else if (request.command === "answer" && session) {
      await session.acceptAnswer(request.sdp);
      send({ ok: true });
    } else if (request.command === "ice" && session) {
      await session.addIceCandidate(request.candidate);
      send({ ok: true });
    } else if (request.command === "close") {
      await stop();
      break;
    } else {
      throw new Error("Invalid IPC command");
    }
  }
} catch {
  // Never print raw exceptions, input messages, SDP or camera credentials.
  send({ ok: false, error: "Camera media operation failed" });
  await stop();
}
