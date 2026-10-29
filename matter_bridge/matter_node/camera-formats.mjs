// Shared by the encoder and Matter allocation validation.
export const VIDEO_FORMAT = Object.freeze({ width: 640, height: 360, fps: 30,
  bitRate: 600_000, keyFrameInterval: 1000 });
export const AUDIO_FORMAT = Object.freeze({ channelCount: 2, sampleRate: 48_000,
  bitRate: 32_000, bitDepth: 16 });
