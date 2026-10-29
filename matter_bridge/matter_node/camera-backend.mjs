import { isIP } from "node:net";

export function createCameraBackend(apiUrl, deviceId, profile, { fetchImpl = fetch } = {}) {
  const base = new URL(apiUrl);
  if (base.protocol !== "http:" || base.username || base.password ||
      !(base.hostname === "localhost" || base.hostname === "[::1]" ||
        (isIP(base.hostname) === 4 && base.hostname.startsWith("127.")))) {
    throw new Error("Camera backend must use loopback HTTP");
  }
  async function request(path, method, body) {
    try {
      const response = await fetchImpl(new URL(path, base), {
        method, redirect: "error", signal: AbortSignal.timeout(25_000),
        headers: { "Content-Type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!response.ok) { await response.body?.cancel(); throw new Error(); }
      if (response.status === 204) return;
      let text = "";
      let bytes = 0;
      const decoder = new TextDecoder();
      for await (const chunk of response.body) {
        bytes += chunk.length;
        if (bytes > 128 * 1024) throw new Error();
        text += decoder.decode(chunk, { stream: true });
      }
      return JSON.parse(text + decoder.decode());
    } catch { throw new Error("Camera backend operation failed"); }
  }
  const sessionPath = handle => `/api/camera-sessions/${encodeURIComponent(handle)}`;
  return {
    create: ({ sdp, audio }) => request(`/api/devices/onvif/${encodeURIComponent(deviceId)}/sessions`,
      "POST", { profile, audio, ...(sdp === undefined ? {} : { sdp }) }),
    active: async handle => (await request(sessionPath(handle), "GET")).active === true,
    answer: (handle, sdp) => request(`${sessionPath(handle)}/answer`, "POST", { sdp }),
    ice: (handle, candidate) => request(`${sessionPath(handle)}/ice`, "POST", { candidate }),
    close: handle => request(sessionPath(handle), "DELETE"),
  };
}
