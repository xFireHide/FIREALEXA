import assert from "node:assert/strict";
import test from "node:test";
import { MATTER_EPOCH_OFFSET_US, Status, StatusResponseError, StreamUsage } from "@matter/main/types";
import { CameraAvStreamManagement as Av } from "@matter/main/clusters/camera-av-stream-management";
import { AUDIO_FORMAT, CameraStreams } from "../camera-streams.mjs";
import { createCameraAvServer } from "../camera-av-server.mjs";
import { createCameraProviderServer } from "../camera-provider-server.mjs";
import { CameraTransport } from "../camera-transport.mjs";
import { CameraClock, createCameraTimeServer } from "../camera-time.mjs";
import { Endpoint, Environment, ServerNode } from "@matter/main";
import { CameraDevice } from "@matter/main/devices/camera";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const videoRequest = () => ({ streamUsage: StreamUsage.LiveView, videoCodec: Av.VideoCodec.H264,
  minFrameRate: 15, maxFrameRate: 60, minResolution: { width: 320, height: 180 },
  maxResolution: { width: 1920, height: 1080 }, minBitRate: 100_000, maxBitRate: 2_000_000,
  keyFrameInterval: 1000 });
const audioRequest = () => ({ streamUsage: StreamUsage.LiveView, audioCodec: Av.AudioCodec.Opus, ...AUDIO_FORMAT });
const snapshotRequest = () => ({ imageCodec: Av.ImageCodec.Jpeg, maxFrameRate: 1,
  minResolution: { width: 320, height: 180 }, maxResolution: { width: 1280, height: 720 }, quality: 75 });
const status = expected => error => error instanceof StatusResponseError && error.code === expected;

test("allocation reports the actual encoded format and reuses compatible streams", () => {
  const streams = new CameraStreams({ audio: true });
  const first = streams.allocateVideo(videoRequest());
  assert.deepEqual(streams.allocateVideo(videoRequest()), first);
  assert.equal(streams.allocatedVideoStreams.length, 1);
  assert.deepEqual(streams.allocatedVideoStreams[0].maxResolution, { width: 640, height: 360 });
  assert.equal(streams.allocatedVideoStreams[0].referenceCount, 0);
  streams.allocateAudio(audioRequest());
  assert.equal(streams.allocatedAudioStreams[0].sampleRate, 48000);
  const copy = streams.allocatedVideoStreams;
  copy[0].minResolution.width = 9999;
  assert.equal(streams.allocatedVideoStreams[0].minResolution.width, 640);
});

test("incompatible allocations fail without consuming a stream", () => {
  const streams = new CameraStreams();
  for (const change of [{ videoCodec: Av.VideoCodec.Hevc }, { minFrameRate: 60 },
    { minResolution: { width: 1920, height: 1080 } }, { maxBitRate: 100_000 },
    { keyFrameInterval: 2000 }, { watermarkEnabled: true }, { streamUsage: StreamUsage.Recording }]) {
    assert.throws(() => streams.allocateVideo({ ...videoRequest(), ...change }), status(Status.ConstraintError));
  }
  assert.deepEqual(streams.allocatedVideoStreams, []);
  assert.throws(() => streams.allocateAudio(audioRequest()), status(Status.UnsupportedCommand));
});

test("references are atomic and in-use streams cannot be deallocated", () => {
  const streams = new CameraStreams({ audio: true });
  const video = streams.allocateVideo(videoRequest());
  const audio = streams.allocateAudio(audioRequest());
  assert.throws(() => streams.acquire("bad", { ...video, audioStreamId: 100 }), status(Status.NotFound));
  assert.equal(streams.allocatedVideoStreams[0].referenceCount, 0);
  streams.acquire("one", { ...video, ...audio });
  streams.acquire("two", video);
  assert.equal(streams.allocatedVideoStreams[0].referenceCount, 2);
  assert.equal(streams.allocatedAudioStreams[0].referenceCount, 1);
  assert.throws(() => streams.acquire("three", video), status(Status.ResourceExhausted));
  assert.throws(() => streams.deallocateVideo(video.videoStreamId), status(Status.Busy));
  assert.throws(() => streams.deallocateAudio(audio.audioStreamId), status(Status.Busy));
  streams.release("one");
  streams.release("one");
  streams.deallocateAudio(audio.audioStreamId);
  streams.release("two");
  streams.deallocateVideo(video.videoStreamId);
  assert.deepEqual(streams.allocatedVideoStreams, []);
  assert.notEqual(streams.allocateVideo(videoRequest()).videoStreamId, video.videoStreamId);
});

test("only implemented live-view priority is accepted", () => {
  const streams = new CameraStreams();
  assert.deepEqual(streams.setPriorities([StreamUsage.LiveView]), [StreamUsage.LiveView]);
  assert.throws(() => streams.setPriorities([StreamUsage.Recording]), status(Status.ConstraintError));
});

test("snapshot lease protects its stream and releases encoder capacity", () => {
  const streams = new CameraStreams();
  const snapshot = streams.allocateSnapshot(snapshotRequest());
  const lease = streams.beginSnapshot({ ...snapshot, requestedResolution: { width: 640, height: 360 } });
  assert.equal(streams.allocatedSnapshotStreams[0].referenceCount, 1);
  assert.throws(() => streams.deallocateSnapshot(snapshot.snapshotStreamId), status(Status.Busy));
  assert.throws(() => streams.beginSnapshot({ snapshotStreamId: null,
    requestedResolution: { width: 640, height: 360 } }), status(Status.Busy));
  const video = streams.allocateVideo(videoRequest());
  streams.acquire("one", video);
  assert.throws(() => streams.acquire("two", video), status(Status.ResourceExhausted));
  lease.release();
  lease.release();
  assert.equal(streams.allocatedSnapshotStreams[0].referenceCount, 0);
  streams.acquire("two", video);
  streams.deallocateSnapshot(snapshot.snapshotStreamId);
});

test("Matter behavior updates allocation attributes on an offline endpoint", async t => {
  const directory = await mkdtemp(join(tmpdir(), "firealexa-matter-test-"));
  Environment.default.vars.set("storage.path", directory);
  let monotonic = 0n;
  const clock = new CameraClock({ monotonic: () => monotonic, persist: async () => {} });
  const TimeServer = createCameraTimeServer(clock);
  const node = await ServerNode.create(ServerNode.RootEndpoint.with(TimeServer), { id: "camera-allocation-test" });
  t.after(async () => { await node.close(); await rm(directory, { recursive: true, force: true }); });
  assert.equal(node.stateOf(TimeServer).utcTime, null);
  // matter.js passes epoch-us command fields and attributes as Unix-epoch microseconds.
  await node.act(agent => agent.get(TimeServer).setUtcTime({
    utcTime: MATTER_EPOCH_OFFSET_US + 1000000n, granularity: 3 }));
  monotonic = 250000n;
  assert.equal(node.stateOf(TimeServer).utcTime, MATTER_EPOCH_OFFSET_US + 1250000n);
  assert.equal(node.stateOf(TimeServer).granularity, 2);
  // The first time zone entry is the Matter epoch, which matter.js holds as Unix microseconds.
  assert.equal(node.stateOf(TimeServer).timeZone[0].validAt, MATTER_EPOCH_OFFSET_US);
  await node.act(agent => agent.get(TimeServer).setTimeZone({
    timeZone: [{ offset: -10800, validAt: MATTER_EPOCH_OFFSET_US, name: "America/Sao_Paulo" }] }));
  assert.equal(node.stateOf(TimeServer).timeZone[0].offset, -10800);
  await assert.rejects(node.act(agent => agent.get(TimeServer).setTimeZone({
    timeZone: [{ offset: 0, validAt: MATTER_EPOCH_OFFSET_US + 1n }] })));
  const streams = new CameraStreams();
  const AvServer = createCameraAvServer(streams, { captureSnapshot: async () => {
    throw new Error("private camera detail");
  } });
  const transport = new CameraTransport(streams, { create() { assert.fail("Unauthenticated call reached media backend"); } });
  t.after(() => transport.close());
  const Provider = createCameraProviderServer(transport, AvServer, async () => {
    assert.fail("Unauthenticated call reached signaling callback");
  });
  const endpoint = new Endpoint(CameraDevice.with(AvServer, Provider), {
    id: "camera", cameraAvStreamManagement: {
      maxContentBufferSize: 0, maxNetworkBandwidth: 2_000_000,
      supportedStreamUsages: [StreamUsage.LiveView], streamUsagePriorities: [StreamUsage.LiveView],
      maxConcurrentEncoders: 2, maxEncodedPixelRate: 13_824_000,
      videoSensorParams: { sensorWidth: 640, sensorHeight: 360, maxFps: 30 },
      minViewportResolution: { width: 640, height: 360 },
      rateDistortionTradeOffPoints: [{ codec: Av.VideoCodec.H264,
        resolution: { width: 640, height: 360 }, minBitRate: 600_000 }],
      currentFrameRate: 30, viewport: { x1: 0, y1: 0, x2: 640, y2: 360 },
      snapshotCapabilities: [{ resolution: { width: 640, height: 360 }, maxFrameRate: 1,
        imageCodec: Av.ImageCodec.Jpeg, requiresEncodedPixels: true, requiresHardwareEncoder: false }],
    },
  });
  await node.add(endpoint);
  await assert.rejects(endpoint.act(agent => agent.get(Provider).solicitOffer({})),
    "A local action without an authenticated remote peer must be rejected");
  assert.deepEqual(endpoint.stateOf(Provider).currentSessions, []);
  const result = await endpoint.act(agent => agent.get(AvServer).videoStreamAllocate(videoRequest()));
  assert.equal(endpoint.stateOf(AvServer).allocatedVideoStreams[0].videoStreamId, result.videoStreamId);
  await endpoint.act(agent => agent.get(AvServer).videoStreamDeallocate(result));
  assert.deepEqual(endpoint.stateOf(AvServer).allocatedVideoStreams, []);
  const snapshot = await endpoint.act(agent => agent.get(AvServer).snapshotStreamAllocate(snapshotRequest()));
  await assert.rejects(endpoint.act(agent => agent.get(AvServer).captureSnapshot({ ...snapshot,
    requestedResolution: { width: 640, height: 360 } })), error =>
      error.code === Status.Failure && !error.message.includes("private camera detail"));
  assert.equal(streams.allocatedSnapshotStreams[0].referenceCount, 0);
  await endpoint.act(agent => agent.get(AvServer).snapshotStreamDeallocate(snapshot));
  assert.deepEqual(endpoint.stateOf(AvServer).allocatedSnapshotStreams, []);
});
