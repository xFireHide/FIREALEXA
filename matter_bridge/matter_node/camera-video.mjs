import { spawn } from "node:child_process";
import { createSocket } from "node:dgram";
import { isIPv4 } from "node:net";
import { MediaStreamTrack, RTCPeerConnection, useH264, useOPUS } from "werift";
import { AUDIO_FORMAT, VIDEO_FORMAT } from "./camera-formats.mjs";

// Internal media layer. No HTTP endpoint accepts FFmpeg arguments or source URLs.
export function rtspInput(uri, expectedIp) {
  const octets = String(expectedIp).split(".").map(Number);
  const privateIp = isIPv4(expectedIp) && (octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168) ||
    (octets[0] === 169 && octets[1] === 254));
  let url;
  try { url = new URL(uri); } catch { throw new Error("Invalid camera RTSP source"); }
  if (!privateIp || url.protocol !== "rtsp:" || url.hostname !== expectedIp || url.hash) {
    throw new Error("RTSP source must match the discovered private camera IP");
  }
  return ["-rtsp_transport", "tcp", "-timeout", "10000000", "-i", url.href];
}

export class FfmpegRtpSource {
  #input;
  #executable;
  #sockets = [];
  #audioInput;
  #child;
  #exit;
  #stopping;
  #started = false;
  constructor(inputArgs, { executable = "ffmpeg", audioInput = 0 } = {}) {
    if (!Number.isInteger(audioInput) || audioInput < 0 || audioInput > 16) throw new Error("Invalid audio input");
    this.#input = [...inputArgs];
    this.#executable = executable;
    this.#audioInput = audioInput;
  }

  async #bind(track, onFailure) {
    const socket = createSocket("udp4");
    this.#sockets.push(socket);
    socket.on("message", (packet, remote) => {
      if (remote.address !== "127.0.0.1" || packet.length < 12 || packet[0] >> 6 !== 2) return;
      try { track.writeRtp(packet); } catch { onFailure(new Error("Invalid video RTP packet")); }
    });
    await new Promise((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(0, "127.0.0.1", () => {
        socket.removeListener("error", reject);
        resolve();
      });
    });
    socket.on("error", () => onFailure(new Error("Video RTP socket failed")));
    if (this.#stopping) {
      try { socket.close(); } catch { /* stop() may already have closed it. */ }
      throw new Error("Media source is stopping");
    }
    return socket.address().port;
  }

  async start(track, onFailure, audioTrack) {
    if (this.#started || this.#stopping) throw new Error("Media source cannot be restarted");
    this.#started = true;
    const port = await this.#bind(track, onFailure);
    const audioPort = audioTrack ? await this.#bind(audioTrack, onFailure) : null;
    if (this.#stopping) return;
    const { width, height, fps, bitRate, keyFrameInterval } = VIDEO_FORMAT;
    const gop = String(fps * keyFrameInterval / 1000);
    // Baseline level 3.1 matches useH264's profile-level-id=42e01f.
    // A one-second GOP supplies periodic keyframes even without a PLI handler.
    const args = [
      "-nostdin", "-hide_banner", "-loglevel", "error", ...this.#input,
      "-map", "0:v:0", "-an", "-sn", "-dn", "-c:v", "libx264",
      "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline",
      "-level:v", "3.1", "-pix_fmt", "yuv420p", "-threads", "2",
      "-vf", `scale=${width}:${height}:force_original_aspect_ratio=decrease,pad=${width}:${height}:(ow-iw)/2:(oh-ih)/2`,
      "-r", String(fps), "-g", gop, "-keyint_min", gop, "-sc_threshold", "0",
      "-b:v", String(bitRate), "-maxrate", String(bitRate), "-bufsize", String(bitRate * 2),
      "-f", "rtp", "-payload_type", "96", "-rtpflags", "skip_rtcp",
      `rtp://127.0.0.1:${port}?pkt_size=1200`,
    ];
    if (audioPort !== null) args.push(
      "-map", `${this.#audioInput}:a:0`, "-vn", "-sn", "-dn", "-c:a", "libopus",
      "-ar", String(AUDIO_FORMAT.sampleRate), "-ac", String(AUDIO_FORMAT.channelCount),
      "-b:a", String(AUDIO_FORMAT.bitRate), "-sample_fmt", "s16", "-application", "lowdelay",
      "-frame_duration", "20", "-f", "rtp", "-payload_type", "111", "-rtpflags", "skip_rtcp",
      `rtp://127.0.0.1:${audioPort}?pkt_size=1200`,
    );
    this.#child = spawn(this.#executable, args, { stdio: "ignore", shell: false });
    // Never relay FFmpeg stderr: it may contain the credential-bearing input URL.
    const child = this.#child;
    this.#exit = new Promise(resolve => {
      child.once("error", () => {
        resolve();
        if (!this.#stopping) onFailure(new Error("Unable to start video encoder"));
      });
      child.once("exit", () => {
        resolve();
        if (!this.#stopping) onFailure(new Error("Video encoder stopped"));
      });
    });
  }

  stop() {
    if (this.#stopping) return this.#stopping;
    this.#stopping = (async () => {
      for (const socket of this.#sockets) {
        try { socket.close(); } catch { /* Already closed or not bound. */ }
      }
      if (this.#child && this.#child.exitCode === null && this.#child.signalCode === null) {
        this.#child.kill("SIGTERM");
        const timer = setTimeout(() => this.#child.kill("SIGKILL"), 2000);
        try { await this.#exit; } finally { clearTimeout(timer); }
      }
    })();
    return this.#stopping;
  }
}

export class CameraVideoSession {
  #peer;
  #track;
  #audioTrack;
  #audioTransceiver;
  #source;
  #timer;
  #closing;
  #started = false;
  #offered = false;
  #awaitingAnswer = false;
  #failure;
  #onClose;
  constructor(source, { audio = false, timeoutMs = 30_000, lifetimeMs = 300_000, peerConfig = {}, onFailure = () => {}, onClose = () => {} } = {}) {
    this.#source = source;
    this.#failure = onFailure;
    this.#onClose = onClose;
    this.#track = new MediaStreamTrack({ kind: "video" });
    this.#peer = new RTCPeerConnection({
      ...peerConfig, bundlePolicy: "max-bundle", iceServers: [],
      codecs: { audio: audio ? [useOPUS()] : [], video: [useH264()] },
    });
    this.#peer.addTransceiver(this.#track, { direction: "sendonly" });
    if (audio) {
      this.#audioTrack = new MediaStreamTrack({ kind: "audio" });
      this.#audioTransceiver = this.#peer.addTransceiver(this.#audioTrack, { direction: "sendonly" });
    }
    this.#timer = setTimeout(() => this.#fail("Camera connection timed out"), timeoutMs);
    this.#peer.connectionStateChange.subscribe(state => {
      if (state === "connected" && !this.#started && !this.#closing) {
        this.#started = true;
        clearTimeout(this.#timer);
        this.#timer = setTimeout(() => { void this.close(); }, lifetimeMs);
        const audioTrack = ["sendonly", "sendrecv"].includes(this.#audioTransceiver?.currentDirection)
          ? this.#audioTrack : undefined;
        void this.#source.start(this.#track, () => this.#fail("Camera media source failed"), audioTrack)
          .catch(() => this.#fail("Camera video source failed"));
      } else if (["failed", "closed", "disconnected"].includes(state)) {
        void this.close();
      }
    });
  }

  #fail(message) {
    if (this.#closing) return;
    void this.close();
    this.#failure(new Error(message));
  }

  async answer(sdp) {
    if (this.#offered || this.#closing) throw new Error("Camera session is not available");
    this.#offered = true;
    if (typeof sdp !== "string" || Buffer.byteLength(sdp) > 64 * 1024) {
      await this.close();
      throw new Error("Invalid camera SDP offer");
    }
    try {
      await this.#peer.setRemoteDescription({ type: "offer", sdp });
      await this.#peer.setLocalDescription(await this.#peer.createAnswer());
      const answer = this.#peer.localDescription.sdp;
      if (!/^m=video (?!0 )/m.test(answer) || !/^a=rtpmap:\d+ H264\/90000/m.test(answer)) {
        throw new Error("H264 video was not negotiated");
      }
      return answer;
    } catch {
      await this.close();
      throw new Error("Camera video negotiation failed");
    }
  }

  async offer() {
    if (this.#offered || this.#closing) throw new Error("Camera session is not available");
    this.#offered = true;
    try {
      await this.#peer.setLocalDescription(await this.#peer.createOffer());
      this.#awaitingAnswer = true;
      return this.#peer.localDescription.sdp;
    } catch {
      await this.close();
      throw new Error("Camera video negotiation failed");
    }
  }

  async acceptAnswer(sdp) {
    if (!this.#awaitingAnswer || this.#closing) throw new Error("Camera session is not awaiting an answer");
    this.#awaitingAnswer = false;
    try {
      if (typeof sdp !== "string" || Buffer.byteLength(sdp) > 64 * 1024 ||
          !/^m=video (?!0 )/m.test(sdp) || !/^a=rtpmap:\d+ H264\/90000/m.test(sdp)) {
        throw new Error("Invalid camera SDP answer");
      }
      await this.#peer.setRemoteDescription({ type: "answer", sdp });
    } catch {
      await this.close();
      throw new Error("Camera video negotiation failed");
    }
  }

  async addIceCandidate(candidate) {
    if (!this.#offered || this.#closing) throw new Error("Camera session is not available");
    await this.#peer.addIceCandidate(candidate);
  }

  close() {
    if (this.#closing) return this.#closing;
    clearTimeout(this.#timer);
    // Set the promise before close emits peer state changes.
    this.#closing = Promise.resolve().then(async () => {
      this.#track.stop();
      this.#audioTrack?.stop();
      await Promise.allSettled([this.#source.stop(), this.#peer.close()]);
      this.#onClose();
    });
    return this.#closing;
  }
}
