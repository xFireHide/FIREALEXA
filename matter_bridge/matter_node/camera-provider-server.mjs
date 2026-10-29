import { WebRtcTransportProviderServer } from "@matter/main/behaviors/web-rtc-transport-provider";
import { WebRtcTransportRequestor } from "@matter/main/clusters/web-rtc-transport-requestor";
import { Status, StatusResponseError } from "@matter/main/types";
import { assertRemoteActor, Invoke, NodeSession, PeerAddress } from "@matter/protocol";

export function createMatterCameraSignalSender(node) {
  return async (owner, signal) => {
    const peer = await node.peers.forAddress(PeerAddress(owner));
    let acknowledged = false;
    for await (const batch of peer.interaction.invoke(Invoke({
      endpoint: signal.endpoint, cluster: WebRtcTransportRequestor,
      command: signal.command, fields: signal.payload,
    }))) {
      for (const result of batch) {
        if (result.kind !== "cmd-status" || result.status !== Status.Success) {
          throw new Error("Camera signaling callback failed");
        }
        acknowledged = true;
      }
    }
    if (!acknowledged) throw new Error("Camera signaling callback was not acknowledged");
  };
}

export function createCameraProviderServer(transport, AvServer, sendSignal) {
  let subscribed = false;
  class Provider extends WebRtcTransportProviderServer {
    initialize() {
      this.syncSessions();
      if (!subscribed) {
        subscribed = true;
        const endpoint = this.endpoint;
        transport.subscribe(() => endpoint.act(agent => {
          agent.get(Provider).syncSessions();
          agent.get(AvServer).syncAllocations();
        }));
      }
    }

    syncSessions() { this.state.currentSessions = transport.currentSessions; }

    #owner() {
      assertRemoteActor(this.context);
      NodeSession.assert(this.context.session);
      const { fabricIndex, nodeId } = this.context.session.peerAddress;
      return { fabricIndex, nodeId };
    }

    async #prepare(request, mode) {
      const owner = this.#owner();
      const complete = this.context.interactionComplete;
      if (!complete) throw new StatusResponseError("Camera signaling requires an exchange", Status.UnsupportedAccess);
      const result = await transport.prepare(owner, request, mode);
      this.syncSessions();
      this.agent.get(AvServer).syncAllocations();
      // RemoteActorContext emits this when the incoming exchange closes, after
      // the controller has received the session identifier in our response.
      complete.once(async () => {
        try { await sendSignal(owner, result.signal); }
        catch { await transport.end(owner, result.response).catch(() => {}); }
      });
      return result.response;
    }

    solicitOffer(request) { return this.#prepare(request, "solicit"); }
    provideOffer(request) { return this.#prepare(request, "offer"); }
    async provideAnswer(request) { await transport.answer(this.#owner(), request); this.syncSessions(); }
    async provideIceCandidates(request) { await transport.ice(this.#owner(), request); }
    async endSession(request) {
      await transport.end(this.#owner(), request);
      this.syncSessions();
      this.agent.get(AvServer).syncAllocations();
    }
  }
  return Provider;
}
