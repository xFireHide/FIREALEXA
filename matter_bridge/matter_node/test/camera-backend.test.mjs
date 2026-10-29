import assert from "node:assert/strict";
import test from "node:test";
import { Status } from "@matter/main/types";
import { createCameraBackend } from "../camera-backend.mjs";
import { createMatterCameraSignalSender } from "../camera-provider-server.mjs";

test("media backend keeps profile IDs and explicit audio choice in local requests", async () => {
  const calls = [];
  const backend = createCameraBackend("http://127.0.0.1:8765", "cam", "main", {
    fetchImpl: async (url, options) => {
      calls.push({ url: url.href, ...options });
      return options.method === "DELETE" ? new Response(null, { status: 204 }) :
        Response.json({ session_id: "opaque", type: "offer", sdp: "offer" });
    },
  });
  assert.equal((await backend.create({ audio: false })).type, "offer");
  assert.deepEqual(JSON.parse(calls[0].body), { profile: "main", audio: false });
  assert.equal(calls[0].redirect, "error");
  await backend.close("opaque");
  assert.equal(calls[1].url, "http://127.0.0.1:8765/api/camera-sessions/opaque");
  assert.equal(calls[1].method, "DELETE");
  assert.throws(() => createCameraBackend("http://192.168.1.1", "cam", "main"), /loopback/);
});

test("backend errors never include response bodies or underlying exceptions", async () => {
  const backend = createCameraBackend("http://127.0.0.1:8765", "cam", "main", {
    fetchImpl: async () => { throw new Error("private detail"); },
  });
  await assert.rejects(backend.create({ audio: true }), error => !error.message.includes("private detail"));
});

test("Matter callback is encoded for the authenticated peer and requires success", async () => {
  const owner = { fabricIndex: 1, nodeId: 123n };
  let calls = 0;
  let success = true;
  const sender = createMatterCameraSignalSender({ peers: { forAddress: async address => {
    assert.equal(address.fabricIndex, owner.fabricIndex);
    assert.equal(address.nodeId, owner.nodeId);
    return { interaction: { async *invoke(request) {
      calls++;
      assert.equal(request.commands.size, 1);
      yield [{ kind: "cmd-status", status: success ? Status.Success : Status.NotFound }];
    } } };
  } } });
  const signal = { command: "answer", endpoint: 1, payload: { webRtcSessionId: 0, sdp: "v=0\r\n" } };
  await sender(owner, signal);
  success = false;
  await assert.rejects(sender(owner, signal), /callback failed/);
  assert.equal(calls, 2);
});
