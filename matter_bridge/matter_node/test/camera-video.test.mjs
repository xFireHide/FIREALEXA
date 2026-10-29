import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { once } from "node:events";
import { RTCPeerConnection, useH264, useVP8, useOPUS } from "werift";
import { CameraVideoSession, FfmpegRtpSource, rtspInput } from "../camera-video.mjs";

test("RTSP input is pinned to the discovered private IP", () => {
  assert.ok(rtspInput("rtsp://admin:secret@192.168.1.173/onvif1", "192.168.1.173")
    .includes("rtsp://admin:secret@192.168.1.173/onvif1"));
  for (const uri of ["rtsp://192.168.1.174/onvif1", "file:///etc/passwd",
    "rtsp://example.com/onvif1", "rtsp://192.168.1.173/onvif1#fragment"]) {
    assert.throws(() => rtspInput(uri, "192.168.1.173"));
  }
  assert.throws(() => rtspInput("rtsp://8.8.8.8/live", "8.8.8.8"));
});

for (const initiator of ["receiver", "camera"]) {
for (const mode of ["video", "audio-video", "declined-audio"]) {
test(`FFmpeg ${mode} reaches receiver when ${initiator} initiates`, { timeout: 25_000 }, async t => {
  const audio = mode === "audio-video";
  const peerConfig = { iceAdditionalHostAddresses: ["127.0.0.1"], iceUseIpv6: false, bundlePolicy: "max-bundle" };
  const receiver = new RTCPeerConnection({ ...peerConfig, iceServers: [],
    codecs: { video: [useH264()], audio: audio ? [useOPUS()] : [] } });
  const failures = [];
  const inputs = ["-re", "-f", "lavfi", "-i", "testsrc2=size=640x360:rate=30"];
  if (audio) inputs.push("-re", "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000");
  const source = new FfmpegRtpSource(inputs, { audioInput: 1 });
  const session = new CameraVideoSession(source, {
    audio: mode !== "video", peerConfig, onFailure: e => failures.push(e),
  });
  t.after(async () => { await session.close(); await receiver.close(); });
  receiver.addTransceiver("video", { direction: "recvonly" });
  if (audio) receiver.addTransceiver("audio", { direction: "recvonly" });
  let packetCount = 0;
  let audioPackets = 0;
  let resolvePackets;
  const packets = new Promise(resolve => { resolvePackets = resolve; });
  receiver.onTrack.subscribe(track => {
    track.onReceiveRtp.subscribe(packet => {
      assert.ok(packet.payload.length > 0);
      if (track.kind === "audio") audioPackets++; else packetCount++;
      if (packetCount >= 10 && (!audio || audioPackets >= 10)) resolvePackets();
    });
  });
  if (initiator === "receiver") {
    await receiver.setLocalDescription(await receiver.createOffer());
    const answer = await session.answer(receiver.localDescription.sdp);
    await receiver.setRemoteDescription({ type: "answer", sdp: answer });
  } else {
    await receiver.setRemoteDescription({ type: "offer", sdp: await session.offer() });
    await receiver.setLocalDescription(await receiver.createAnswer());
    await session.acceptAnswer(receiver.localDescription.sdp);
    await assert.rejects(session.acceptAnswer(receiver.localDescription.sdp), /not awaiting/);
  }
  let timer;
  try {
    await Promise.race([packets, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("Expected media packets were not received")), 15_000);
    })]);
  } finally { clearTimeout(timer); }
  assert.deepEqual(failures, []);
  assert.ok(packetCount >= 10);
  if (audio) assert.ok(audioPackets >= 10);
  await session.close();
  await session.close();
  await assert.rejects(session.answer(receiver.localDescription.sdp), /not available/);
});
}
}

test("oversized offer closes without starting its source", async () => {
  let stopped = false;
  const session = new CameraVideoSession({
    start() { assert.fail("Source must not start"); },
    async stop() { stopped = true; },
  });
  await assert.rejects(session.answer("x".repeat(65537)), /Invalid camera SDP/);
  assert.equal(stopped, true);
});

test("unsupported video codec is rejected before the source starts", async t => {
  const receiver = new RTCPeerConnection({ iceServers: [], codecs: { video: [useVP8()] } });
  let stopped = false;
  const session = new CameraVideoSession({
    start() { assert.fail("Source must not start"); },
    async stop() { stopped = true; },
  });
  t.after(async () => { await session.close(); await receiver.close(); });
  receiver.addTransceiver("video", { direction: "recvonly" });
  await receiver.setLocalDescription(await receiver.createOffer());
  await assert.rejects(session.answer(receiver.localDescription.sdp), /negotiation failed/);
  assert.equal(stopped, true);
});

test("private worker negotiates through stdin and exits on close", { timeout: 15_000 }, async t => {
  const receiver = new RTCPeerConnection({ iceServers: [], codecs: { video: [useH264()] } });
  const worker = spawn(process.execPath, [new URL("../camera-worker.mjs", import.meta.url).pathname],
    { stdio: ["pipe", "pipe", "pipe"] });
  const lines = createInterface({ input: worker.stdout });
  const exited = once(worker, "exit");
  let stderr = "";
  worker.stderr.on("data", chunk => { stderr += chunk; });
  t.after(async () => {
    if (worker.exitCode === null) worker.kill("SIGTERM");
    await exited;
    lines.close();
    await receiver.close();
  });
  receiver.addTransceiver("video", { direction: "recvonly" });
  await receiver.setLocalDescription(await receiver.createOffer());
  const reply = once(lines, "line");
  worker.stdin.write(JSON.stringify({ command: "offer", sdp: receiver.localDescription.sdp,
    source: { uri: "rtsp://user:private-password@192.168.1.173/live", ip: "192.168.1.173" } }) + "\n");
  const [line] = await reply;
  const answer = JSON.parse(line);
  assert.equal(answer.ok, true);
  assert.match(answer.sdp, /H264\/90000/);
  assert.ok(!line.includes("private-password"));
  // Do not set the remote answer: no ICE connection, so no camera is contacted.
  worker.stdin.write('{"command":"close"}\n');
  const [code] = await exited;
  assert.equal(code, 0);
  assert.ok(!stderr.includes("private-password"));
});
