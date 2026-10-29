import assert from "node:assert/strict";
import test from "node:test";
import { Status, StreamUsage } from "@matter/main/types";
import { CameraStreams, VIDEO_FORMAT } from "../camera-streams.mjs";
import { CameraTransport } from "../camera-transport.mjs";

const owner = { fabricIndex: 1, nodeId: 123n };
function fixture(overrides = {}) {
  const streams = new CameraStreams();
  const { width, height, fps, bitRate, keyFrameInterval } = VIDEO_FORMAT;
  const video = streams.allocateVideo({ streamUsage: StreamUsage.LiveView, videoCodec: 0,
    minFrameRate: fps, maxFrameRate: fps, minResolution: { width, height },
    maxResolution: { width, height }, minBitRate: bitRate, maxBitRate: bitRate, keyFrameInterval });
  const calls = [];
  const backend = {
    create: async args => { calls.push(["create", args]); return {
      session_id: "private-handle", sdp: "backend-sdp", type: args.sdp ? "answer" : "offer" }; },
    answer: async (...args) => calls.push(["answer", ...args]),
    ice: async (...args) => calls.push(["ice", ...args]),
    close: async (...args) => calls.push(["close", ...args]), ...overrides,
  };
  return { streams, calls, transport: new CameraTransport(streams, backend),
    request: { ...video, streamUsage: StreamUsage.LiveView, originatingEndpointId: 1 } };
}

test("sessions are scoped to fabric AND node, with no backend handle in attributes", async t => {
  const { transport, request, streams, calls } = fixture();
  t.after(() => transport.close());
  const { response, signal } = await transport.prepare(owner, request, "solicit");
  assert.equal(signal.command, "offer");
  assert.equal(response.deferredOffer, false);
  assert.equal(streams.allocatedVideoStreams[0].referenceCount, 1);
  assert.ok(!Object.values(transport.currentSessions[0]).includes("private-handle"));
  for (const wrong of [{ ...owner, nodeId: 124n }, { ...owner, fabricIndex: 2 }]) {
    await assert.rejects(transport.end(wrong, response), e => e.code === Status.NotFound);
    await assert.rejects(transport.answer(wrong, { ...response, sdp: "answer" }), e => e.code === Status.NotFound);
    await assert.rejects(transport.ice(wrong, { ...response, iceCandidates: [{ candidate: "" }] }), e => e.code === Status.NotFound);
  }
  assert.equal(calls.length, 1);
  await transport.answer(owner, { ...response, sdp: "answer" });
  await assert.rejects(transport.answer(owner, { ...response, sdp: "answer" }), e => e.code === Status.InvalidInState);
  await transport.ice(owner, { ...response, iceCandidates: [{ candidate: "candidate", sdpMid: "0", sdpmLineIndex: 0 }] });
  assert.deepEqual(calls.at(-1), ["ice", "private-handle", { candidate: "candidate", sdpMid: "0", sdpMLineIndex: 0 }]);
  await transport.end(owner, response);
  assert.equal(streams.allocatedVideoStreams[0].referenceCount, 0);
  assert.deepEqual(transport.currentSessions, []);
});

test("provider answer flow forwards only allocated media choices", async t => {
  const { transport, request, calls } = fixture();
  t.after(() => transport.close());
  const result = await transport.prepare(owner, { ...request, webRtcSessionId: null, sdp: "offer" }, "offer");
  assert.equal(result.signal.command, "answer");
  assert.deepEqual(calls[0], ["create", { sdp: "offer", audio: false }]);
  await assert.rejects(transport.answer(owner, { ...result.response, sdp: "answer" }), e => e.code === Status.InvalidInState);
});

test("backend failure releases allocation and redacts private error text", async () => {
  const { transport, request, streams } = fixture({ create: async () => { throw new Error("rtsp://secret"); } });
  await assert.rejects(transport.prepare(owner, request, "solicit"), e =>
    e.code === Status.Failure && !e.message.includes("secret"));
  assert.equal(streams.allocatedVideoStreams[0].referenceCount, 0);
  await transport.close();
});

test("shutdown during negotiation closes a late worker and releases references", async () => {
  let resolve;
  const pending = new Promise(r => { resolve = r; });
  const { transport, request, streams, calls } = fixture({ create: () => pending });
  const result = transport.prepare(owner, request, "solicit");
  await transport.close();
  resolve({ session_id: "late", sdp: "offer", type: "offer" });
  await assert.rejects(result, e => e.code === Status.InvalidInState);
  assert.equal(streams.allocatedVideoStreams[0].referenceCount, 0);
  assert.deepEqual(calls, [["close", "late"]]);
});

test("unsupported options are rejected before creating a worker", async () => {
  const { transport, request, calls } = fixture();
  for (const extra of [{ metadataEnabled: true }, { iceTransportPolicy: "relay" },
    { videoStreams: [] }, { videoStreams: [0, 1] }, { iceServers: [{ urls: ["stun:example.com"] }] }]) {
    await assert.rejects(transport.prepare(owner, { ...request, ...extra }, "solicit"), e => e.code === Status.ConstraintError);
  }
  assert.deepEqual(calls, []);
  await transport.close();
});
