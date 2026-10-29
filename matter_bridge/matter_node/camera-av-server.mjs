import { CameraAvStreamManagementServer } from "@matter/main/behaviors/camera-av-stream-management";
import { CameraAvStreamManagement } from "@matter/main/clusters/camera-av-stream-management";
import { Status, StatusResponseError } from "@matter/main/types";

/** Per-camera allocation handlers. Endpoint publication and media-session
 * lifecycle must supply the required capability attributes and synchronize
 * reference counts with syncAllocations(). No camera is published by this file.
 */
export function createCameraAvServer(streams, { captureSnapshot } = {}) {
  const features = streams.audioSupported ? ["Video", "Audio"] : ["Video"];
  if (captureSnapshot) features.push("Snapshot");
  const Base = CameraAvStreamManagementServer.with(...features);
  return class CameraAvServer extends Base {
    initialize() { this.syncAllocations(); }

    syncAllocations() {
      this.state.allocatedVideoStreams = streams.allocatedVideoStreams;
      if (streams.audioSupported) this.state.allocatedAudioStreams = streams.allocatedAudioStreams;
      if (captureSnapshot) this.state.allocatedSnapshotStreams = streams.allocatedSnapshotStreams;
    }

    videoStreamAllocate(request) {
      const result = streams.allocateVideo(request);
      this.syncAllocations();
      return result;
    }

    videoStreamDeallocate({ videoStreamId }) {
      streams.deallocateVideo(videoStreamId);
      this.syncAllocations();
    }

    audioStreamAllocate(request) {
      const result = streams.allocateAudio(request);
      this.syncAllocations();
      return result;
    }

    audioStreamDeallocate({ audioStreamId }) {
      streams.deallocateAudio(audioStreamId);
      this.syncAllocations();
    }

    setStreamPriorities({ streamPriorities }) {
      this.state.streamUsagePriorities = streams.setPriorities(streamPriorities);
    }

    snapshotStreamAllocate(request) {
      const result = streams.allocateSnapshot(request);
      this.syncAllocations();
      return result;
    }

    snapshotStreamDeallocate({ snapshotStreamId }) {
      streams.deallocateSnapshot(snapshotStreamId);
      this.syncAllocations();
    }

    async captureSnapshot(request) {
      if (!captureSnapshot) throw new StatusResponseError("Snapshots unavailable", Status.UnsupportedCommand);
      const lease = streams.beginSnapshot(request);
      this.syncAllocations();
      try {
        const { data, resolution } = await captureSnapshot(lease.quality);
        return { data, resolution, imageCodec: CameraAvStreamManagement.ImageCodec.Jpeg };
      } catch {
        throw new StatusResponseError("Camera snapshot failed", Status.Failure);
      } finally {
        lease.release();
        this.syncAllocations();
      }
    }
  };
}
