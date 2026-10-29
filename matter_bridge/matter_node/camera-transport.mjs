import { Status, StatusResponseError, StreamUsage } from "@matter/main/types";
import { WebRtcTransportDefinitions } from "@matter/main/clusters/web-rtc-transport-definitions";

const fail = (message, code = Status.ConstraintError) => { throw new StatusResponseError(message, code); };
function ownerKey(owner) {
  if (!Number.isInteger(owner?.fabricIndex) || owner.fabricIndex < 1 || owner.fabricIndex > 254 ||
      typeof owner.nodeId !== "bigint" || owner.nodeId <= 0n) fail("Secure Matter peer required", Status.UnsupportedAccess);
  return `${owner.fabricIndex}:${owner.nodeId}`;
}

/** Provider session coordinator. The Matter handler must obtain owner from its
 * authenticated CASE session, never from request fields. Backend handles remain
 * private and are not included in currentSessions or Matter responses.
 */
export class CameraTransport {
  #streams;
  #backend;
  #sessions = new Map();
  #nextId = 0;
  #closed = false;
  #lifetimeMs;
  #onPeerEnd;
  #listeners = new Set();
  constructor(streams, backend, { lifetimeMs = 300_000, onPeerEnd = async () => {} } = {}) {
    this.#streams = streams;
    this.#backend = backend;
    this.#lifetimeMs = lifetimeMs;
    this.#onPeerEnd = onPeerEnd;
  }

  subscribe(listener) { this.#listeners.add(listener); return () => this.#listeners.delete(listener); }
  #notify() { for (const listener of this.#listeners) queueMicrotask(() => { void Promise.resolve().then(listener).catch(() => {}); }); }

  get currentSessions() {
    return [...this.#sessions.values()].filter(s => s.handle).map(s => ({
      id: s.id, fabricIndex: s.owner.fabricIndex, peerNodeId: s.owner.nodeId,
      peerEndpointId: s.endpoint, streamUsage: StreamUsage.LiveView,
      videoStreamId: s.videoStreamId, audioStreamId: s.audioStreamId,
      videoStreams: [s.videoStreamId], audioStreams: s.audioStreamId === null ? [] : [s.audioStreamId],
      metadataEnabled: false,
    }));
  }

  #find(owner, id) {
    const key = ownerKey(owner);
    const session = this.#sessions.get(id);
    if (!session || session.ownerKey !== key || !session.handle) fail("Unknown camera session", Status.NotFound);
    return session;
  }

  async prepare(owner, request, mode) {
    const key = ownerKey(owner);
    if (this.#closed) fail("Camera transport closed", Status.InvalidInState);
    if (mode !== "offer" && mode !== "solicit") fail("Invalid negotiation mode");
    if (request.webRtcSessionId !== undefined && request.webRtcSessionId !== null) {
      // Re-offers need explicit media replacement and are not yet implemented.
      this.#find(owner, request.webRtcSessionId);
      fail("Camera re-offer is not implemented", Status.InvalidInState);
    }
    if (request.streamUsage !== StreamUsage.LiveView || !Number.isInteger(request.originatingEndpointId) ||
        request.originatingEndpointId < 0 || request.originatingEndpointId > 65534 ||
        request.metadataEnabled === true || request.iceServers?.length ||
        (request.iceTransportPolicy !== undefined && request.iceTransportPolicy !== "all")) {
      fail("Unsupported camera session options");
    }
    if (mode === "offer" && (typeof request.sdp !== "string" || !request.sdp.length ||
        Buffer.byteLength(request.sdp) > 65536)) fail("Invalid SDP offer");
    const select = (list, legacy, required) => {
      if (list !== undefined && (!Array.isArray(list) || list.length > 1)) fail("Only one stream per media kind is supported");
      const value = list === undefined ? legacy ?? null : list[0] ?? null;
      if (list !== undefined && legacy !== undefined && legacy !== null && value !== legacy) fail("Conflicting stream identifiers");
      if ((required && value === null) || (value !== null && (!Number.isInteger(value) || value < 0 || value > 65535))) {
        fail("An allocated video stream is required");
      }
      return value;
    };
    const automaticVideo = request.videoStreams === undefined && request.videoStreamId === null;
    const automaticAudio = request.audioStreams === undefined && request.audioStreamId === null;
    if (this.#sessions.size >= 2) fail("Camera session capacity reached", Status.ResourceExhausted);
    if (automaticAudio && !this.#streams.audioSupported) fail("Camera profile has no audio", Status.UnsupportedCommand);
    const videoStreamId = automaticVideo
      ? this.#streams.ensureVideoAllocated().videoStreamId
      : select(request.videoStreams, request.videoStreamId, true);
    const audioStreamId = automaticAudio
      ? this.#streams.ensureAudioAllocated().audioStreamId
      : select(request.audioStreams, request.audioStreamId, false);
    let id;
    do { id = this.#nextId++ % 65536; } while (this.#sessions.has(id));
    const reference = `rtc:${id}`;
    this.#streams.acquire(reference, { videoStreamId, audioStreamId });
    const session = { id, owner: { ...owner }, ownerKey: key, reference,
      videoStreamId, audioStreamId, endpoint: request.originatingEndpointId,
      phase: "preparing", handle: null, timer: null, monitorTimer: null };
    this.#sessions.set(id, session);
    try {
      const result = await this.#backend.create({ sdp: mode === "offer" ? request.sdp : undefined,
        audio: audioStreamId !== null });
      session.handle = result.session_id;
      if (this.#closed || this.#sessions.get(id) !== session) {
        await this.#backend.close(session.handle);
        fail("Camera transport closed", Status.InvalidInState);
      }
      if (typeof result.session_id !== "string" || !result.session_id ||
          typeof result.sdp !== "string" || !result.sdp.length || Buffer.byteLength(result.sdp) > 65536 ||
          result.type !== (mode === "solicit" ? "offer" : "answer")) throw new Error("Invalid backend response");
      session.phase = mode === "solicit" ? "awaiting-answer" : "answer-ready";
      session.timer = setTimeout(() => {
        void this.#end(session, WebRtcTransportDefinitions.WebRtcEndReason.MediaTimeout);
      }, this.#lifetimeMs);
      this.#scheduleMonitor(session);
      this.#notify();
      return { response: { webRtcSessionId: id, videoStreamId, audioStreamId,
        ...(mode === "solicit" ? { deferredOffer: false } : {}) },
      signal: { command: mode === "solicit" ? "offer" : "answer",
        endpoint: session.endpoint, payload: { webRtcSessionId: id, sdp: result.sdp } } };
    } catch (error) {
      await this.#end(session);
      if (error instanceof StatusResponseError) throw error;
      fail("Camera negotiation failed", Status.Failure);
    }
  }

  async answer(owner, { webRtcSessionId, sdp }) {
    const session = this.#find(owner, webRtcSessionId);
    if (session.phase !== "awaiting-answer") fail("Session is not awaiting an answer", Status.InvalidInState);
    if (typeof sdp !== "string" || !sdp.length || Buffer.byteLength(sdp) > 65536) fail("Invalid SDP answer");
    session.phase = "answering";
    try {
      await this.#backend.answer(session.handle, sdp);
      session.phase = "active";
    } catch {
      await this.#end(session);
      fail("Camera answer failed", Status.Failure);
    }
  }

  async ice(owner, { webRtcSessionId, iceCandidates }) {
    const session = this.#find(owner, webRtcSessionId);
    if (!Array.isArray(iceCandidates) || iceCandidates.length < 1 || iceCandidates.length > 32) fail("Invalid ICE candidates");
    for (const candidate of iceCandidates) {
      if (typeof candidate?.candidate !== "string" || candidate.candidate.length > 4096) fail("Invalid ICE candidate");
    }
    try {
      for (const candidate of iceCandidates) {
        await this.#backend.ice(session.handle, { candidate: candidate.candidate,
          sdpMid: candidate.sdpMid, sdpMLineIndex: candidate.sdpmLineIndex });
      }
    } catch {
      await this.#end(session);
      fail("Camera ICE exchange failed", Status.Failure);
    }
  }

  async end(owner, { webRtcSessionId }) { await this.#end(this.#find(owner, webRtcSessionId)); }

  async closeFabric(fabricIndex) {
    if (!Number.isInteger(fabricIndex) || fabricIndex < 1 || fabricIndex > 254) return;
    await Promise.all([...this.#sessions.values()]
      .filter(session => session.owner.fabricIndex === fabricIndex)
      .map(session => this.#end(session)));
  }

  async #end(session, peerEndReason) {
    if (this.#sessions.get(session.id) !== session) return;
    this.#sessions.delete(session.id);
    clearTimeout(session.timer);
    clearTimeout(session.monitorTimer);
    try { if (session.handle) await this.#backend.close(session.handle); }
    catch { /* Still release local references after a backend crash. */ }
    finally { this.#streams.release(session.reference); this.#notify(); }
    if (peerEndReason !== undefined) {
      try {
        await this.#onPeerEnd(session.owner, {
          endpoint: session.endpoint,
          payload: { webRtcSessionId: session.id, reason: peerEndReason },
        });
      } catch {
        // The local session and stream allocation are already released.
      }
    }
  }

  #scheduleMonitor(session) {
    if (typeof this.#backend.active !== "function" || this.#sessions.get(session.id) !== session) return;
    session.monitorTimer = setTimeout(async () => {
      try {
        if (!await this.#backend.active(session.handle)) {
          await this.#end(session, WebRtcTransportDefinitions.WebRtcEndReason.UnknownReason);
          return;
        }
      } catch {
        // A transient loopback API error must not tear down a live stream.
      }
      this.#scheduleMonitor(session);
    }, 5_000);
    session.monitorTimer.unref?.();
  }

  async close() {
    this.#closed = true;
    await Promise.all([...this.#sessions.values()].map(session => this.#end(session)));
    this.#listeners.clear();
  }
}
