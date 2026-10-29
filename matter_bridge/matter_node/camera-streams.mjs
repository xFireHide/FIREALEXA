import { Status, StatusResponseError, StreamUsage } from "@matter/main/types";
import { CameraAvStreamManagement } from "@matter/main/clusters/camera-av-stream-management";

import { AUDIO_FORMAT, VIDEO_FORMAT } from "./camera-formats.mjs";
import { SNAPSHOT_FORMAT } from "./camera-snapshot.mjs";
export { AUDIO_FORMAT, VIDEO_FORMAT } from "./camera-formats.mjs";
const fail = (message, status = Status.ConstraintError) => {
  throw new StatusResponseError(message, status);
};
const contains = (minimum, maximum, value) => Number.isInteger(minimum) &&
  Number.isInteger(maximum) && minimum > 0 && minimum <= value && maximum >= value;
const liveView = request => {
  if (request.streamUsage !== StreamUsage.LiveView) fail("Only live view is supported");
};

/** Allocation bookkeeping for the fixed media pipeline, independent of network I/O.
 * Sessions own references; allocation by itself does not start an encoder.
 */
export class CameraStreams {
  #video = null;
  #audio = null;
  #sessions = new Map();
  #audioSupported;
  #nextVideoId = 0;
  #nextAudioId = 0;
  #snapshot = null;
  #nextSnapshotId = 0;
  #snapshotBusy = false;
  constructor({ audio = false } = {}) { this.#audioSupported = audio; }
  get audioSupported() { return this.#audioSupported; }

  get allocatedVideoStreams() { return this.#video ? [structuredClone(this.#video)] : []; }
  get allocatedAudioStreams() { return this.#audio ? [structuredClone(this.#audio)] : []; }
  get allocatedSnapshotStreams() { return this.#snapshot ? [structuredClone(this.#snapshot)] : []; }

  allocateSnapshot(request) {
    const { width, height, frameRate } = SNAPSHOT_FORMAT;
    if (request.imageCodec !== CameraAvStreamManagement.ImageCodec.Jpeg ||
        !Number.isInteger(request.maxFrameRate) || request.maxFrameRate < frameRate ||
        !contains(request.minResolution?.width, request.maxResolution?.width, width) ||
        !contains(request.minResolution?.height, request.maxResolution?.height, height) ||
        !Number.isInteger(request.quality) || request.quality < 1 || request.quality > 100 ||
        request.watermarkEnabled === true || request.osdEnabled === true) {
      fail("Requested snapshot format is not supported");
    }
    if (this.#snapshot && this.#snapshot.quality !== request.quality) {
      fail("Snapshot encoder is already allocated", Status.ResourceExhausted);
    }
    this.#snapshot ??= { snapshotStreamId: this.#nextSnapshotId++ % 65536,
      imageCodec: CameraAvStreamManagement.ImageCodec.Jpeg, frameRate,
      minResolution: { width, height }, maxResolution: { width, height }, quality: request.quality,
      referenceCount: 0, encodedPixels: true, hardwareEncoder: false };
    return { snapshotStreamId: this.#snapshot.snapshotStreamId };
  }

  deallocateSnapshot(id) {
    if (this.#snapshot?.snapshotStreamId !== id) fail("Unknown snapshot stream", Status.NotFound);
    if (this.#snapshot.referenceCount) fail("Snapshot stream is in use", Status.Busy);
    this.#snapshot = null;
  }

  beginSnapshot({ snapshotStreamId, requestedResolution }) {
    if (!Number.isInteger(requestedResolution?.width) || requestedResolution.width < 1 ||
        !Number.isInteger(requestedResolution?.height) || requestedResolution.height < 1) {
      fail("Invalid snapshot resolution");
    }
    if (snapshotStreamId !== null && this.#snapshot?.snapshotStreamId !== snapshotStreamId) {
      fail("Unknown snapshot stream", Status.NotFound);
    }
    if (this.#snapshotBusy || this.#sessions.size >= 2) fail("Snapshot encoder is busy", Status.Busy);
    this.#snapshotBusy = true;
    const allocated = snapshotStreamId !== null ? this.#snapshot : null;
    if (allocated) allocated.referenceCount++;
    let done = false;
    return { quality: allocated?.quality ?? SNAPSHOT_FORMAT.quality, release: () => {
      if (done) return;
      done = true;
      this.#snapshotBusy = false;
      if (allocated) allocated.referenceCount--;
    } };
  }

  allocateVideo(request) {
    liveView(request);
    const { width, height, fps, bitRate, keyFrameInterval } = VIDEO_FORMAT;
    if (request.videoCodec !== CameraAvStreamManagement.VideoCodec.H264 ||
        !contains(request.minFrameRate, request.maxFrameRate, fps) ||
        !contains(request.minResolution?.width, request.maxResolution?.width, width) ||
        !contains(request.minResolution?.height, request.maxResolution?.height, height) ||
        !contains(request.minBitRate, request.maxBitRate, bitRate) ||
        request.keyFrameInterval !== keyFrameInterval ||
        request.watermarkEnabled === true || request.osdEnabled === true) {
      fail("Requested video format is not supported");
    }
    if (!this.#video) {
      this.#video = { videoStreamId: this.#nextVideoId++ % 65536,
        streamUsage: StreamUsage.LiveView, videoCodec: CameraAvStreamManagement.VideoCodec.H264,
        minFrameRate: fps, maxFrameRate: fps,
        minResolution: { width, height }, maxResolution: { width, height },
        minBitRate: bitRate, maxBitRate: bitRate, keyFrameInterval, referenceCount: 0 };
    }
    return { videoStreamId: this.#video.videoStreamId };
  }

  ensureVideoAllocated() {
    const { width, height, fps, bitRate, keyFrameInterval } = VIDEO_FORMAT;
    return this.allocateVideo({ streamUsage: StreamUsage.LiveView,
      videoCodec: CameraAvStreamManagement.VideoCodec.H264,
      minFrameRate: fps, maxFrameRate: fps,
      minResolution: { width, height }, maxResolution: { width, height },
      minBitRate: bitRate, maxBitRate: bitRate, keyFrameInterval,
      watermarkEnabled: false, osdEnabled: false });
  }

  allocateAudio(request) {
    if (!this.#audioSupported) fail("Camera profile has no audio", Status.UnsupportedCommand);
    liveView(request);
    if (request.audioCodec !== CameraAvStreamManagement.AudioCodec.Opus ||
        Object.entries(AUDIO_FORMAT).some(([key, value]) => request[key] !== value)) {
      fail("Requested audio format is not supported");
    }
    if (!this.#audio) {
      this.#audio = { audioStreamId: this.#nextAudioId++ % 65536,
        streamUsage: StreamUsage.LiveView, audioCodec: CameraAvStreamManagement.AudioCodec.Opus,
        ...AUDIO_FORMAT, referenceCount: 0 };
    }
    return { audioStreamId: this.#audio.audioStreamId };
  }

  ensureAudioAllocated() {
    return this.allocateAudio({ streamUsage: StreamUsage.LiveView,
      audioCodec: CameraAvStreamManagement.AudioCodec.Opus,
      ...AUDIO_FORMAT });
  }

  deallocateVideo(id) {
    if (this.#video?.videoStreamId !== id) fail("Unknown video stream", Status.NotFound);
    if (this.#video.referenceCount) fail("Video stream is in use", Status.Busy);
    this.#video = null;
  }

  deallocateAudio(id) {
    if (this.#audio?.audioStreamId !== id) fail("Unknown audio stream", Status.NotFound);
    if (this.#audio.referenceCount) fail("Audio stream is in use", Status.Busy);
    this.#audio = null;
  }

  acquire(sessionKey, { videoStreamId, audioStreamId = null }) {
    if (this.#sessions.has(sessionKey)) fail("Session already has streams", Status.InvalidInState);
    if (this.#sessions.size + Number(this.#snapshotBusy) >= 2) fail("Camera encoder capacity reached", Status.ResourceExhausted);
    // Validate both before changing either reference count.
    if (this.#video?.videoStreamId !== videoStreamId) fail("Unknown video stream", Status.NotFound);
    if (audioStreamId !== null && this.#audio?.audioStreamId !== audioStreamId) {
      fail("Unknown audio stream", Status.NotFound);
    }
    this.#sessions.set(sessionKey, { videoStreamId, audioStreamId });
    this.#video.referenceCount++;
    if (audioStreamId !== null) this.#audio.referenceCount++;
  }

  release(sessionKey) {
    const streams = this.#sessions.get(sessionKey);
    if (!streams) return;
    this.#sessions.delete(sessionKey);
    this.#video.referenceCount--;
    if (streams.audioStreamId !== null) this.#audio.referenceCount--;
  }

  setPriorities(priorities) {
    if (!Array.isArray(priorities) || priorities.length !== 1 || priorities[0] !== StreamUsage.LiveView) {
      fail("Only the live-view stream priority is supported");
    }
    return [...priorities];
  }
}
