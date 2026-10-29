# Matter Bridge

Local async bridge for eWeLink/Sonoff, Broadlink, Xiaomi miIO and ONVIF camera discovery. Python handles discovery and device protocols; a small `matter.js` runtime publishes supported bridged Matter endpoints over the local API.

## Install and run

Requires Python 3.11+.
Matter publication requires Node.js 22.13+ and npm.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m ensurepip --upgrade
python -m pip install -e .
(cd matter_bridge/matter_node && npm install)
matter-bridge --config ./matter-bridge.json
```

Run the local regression suite with `python -m unittest discover -s matter_bridge/tests -v`.
The crypto round-trip cases run when the installed project dependencies include `cryptography`.

For a wheel or system-wide Python installation where the installed package directory is not writable, the Matter provider copies its JavaScript runtime to `matter-storage/runtime` beside the registry. The first startup reports the exact dependency install command for that runtime directory; run it once, then restart the bridge. This keeps npm files and Matter storage out of Python's `site-packages`.

Optional `config.json` next to the registry file can provide eWeLink keys:

```json
{"ewelink_apikeys": {"device-id": "local-api-key"}}
```

For ONVIF cameras, configure credentials keyed by the camera UUID returned by `GET /api/devices` (the `urn:uuid:` prefix is removed):

```json
{
  "onvif_credentials": {
    "camera-uuid": {"username": "admin", "password": "camera-password"}
  }
}
```

The app uses WS-Security UsernameToken and falls back to HTTP Digest when challenged. Credentials remain in the private `config.json`; do not expose that file. After discovery and successful authentication, the local API lists ONVIF profiles with opaque selectors; the RTSP URIs stay inside the authenticated media backend. When the camera advertises ONVIF Events, the adapter creates a PullPoint subscription and maps recognized motion-topic state values to a Matter Occupancy Sensor endpoint; unsupported event topics leave the camera without a motion endpoint. Retrieve a JPEG snapshot with `GET /api/devices/onvif/{device_id}/snapshot?profile={profile_token}`, using a profile selector returned in the device's `camera.profiles` list. The route is loopback-only, pins the camera-returned URI to the discovered camera IP, rejects redirects, and caps the image at 8 MiB. A PTZ move can be sent through the loopback-only state endpoint, for example `PUT /api/devices/onvif/camera-uuid/state` with `{"ptz":{"direction":"up","duration_ms":500,"speed":0.5}}`. Directions are `up`, `down`, `left`, `right`, the four diagonals, or `stop`; the adapter limits move duration to 100–5000 ms and sends a stop command after a move.

For EseeCloud-compatible cameras whose owner has confirmed the local HTTP stream path, add an explicit source to the same private `config.json`. This does not scan the network or claim that every EseeCloud model uses this protocol:

```json
{
  "eseecloud_streams": {
    "front-yard": {
      "ip": "192.168.1.50",
      "port": 80,
      "channel": 12,
      "username": "admin",
      "password": "camera-password",
      "name": "Front Yard Camera"
    }
  }
}
```

The adapter accepts only private/link-local IPv4 targets and constructs `/livestream/{channel}` itself. `GET /api/devices/eseecloud/front-yard/stream-info` briefly opens the source and reports its supported video/audio codec names and RTP payload metadata; it does not return credentials. `GET /api/devices/eseecloud/front-yard/stream` proxies the raw framed media and is loopback-only; it validates the H.264/H.265 preamble and bounded frame lengths, but does not decode or convert the stream. It allows at most two simultaneous viewers per camera. The channel and credentials must match the camera firmware. This feed is not yet a Matter Camera/WebRTC endpoint.

The ONVIF adapter also probes the documented Yoosee/XM UDP discovery port. A response matching the probe's weak `70 02` prefix becomes a camera candidate only after TCP ports 5000 (ONVIF) and 554 (RTSP) accept connections. These candidates appear with IDs such as `yoosee-xm-192-168-1-20`; use that ID in `onvif_credentials`. The API labels this as discovery protocol `xm_udp_8899` and vendor hint `Yoosee/XM (unverified)`. This does not confirm the vendor or authenticate the camera. The XM response format and this fallback still need target-capture validation; EseeCloud is not identified by this probe.

On the first run the app creates `config.json` beside the registry, with a random Matter setup code, discriminator, stable bridge ID, and development VID/PID (`0xFFF1`/`0x8000`). Keep this file private; it preserves the Matter commissioning identity. While the bridge is uncommissioned, its logs include the QR code, a QR URL, and the manual pairing code. Fabric and node storage is persisted in the sibling `matter-storage/` directory with owner-only permissions. The default VID is for development and the runtime does not currently load manufacturer DAC/PAI certificates or a signed Certification Declaration. Setting another VID/PID in `config.json` does not supply those credentials or establish ecosystem compatibility. Apple Home/Google Home commissioning must be validated with appropriate attestation credentials; the current runtime is suitable for development controllers that accept test devices.

If setting `matter.node_id` manually, use 1–32 ASCII letters, digits, underscores, or hyphens. The value is also published as the bridge serial and unique ID.

Xiaomi devices require their 32-hex-character local miIO token keyed by numeric device ID:

```json
{"xiaomi_tokens": {"123456789": "0123456789abcdef0123456789abcdef"}}
```

Learn each Broadlink IR code by posting to `/api/devices/broadlink/{device_id}/learn-ir` while pointing the original remote at the RM unit and pressing the button; the response contains `ir_data` as hex. This command follows the same origin policy as control commands and is loopback-only by default.

Broadlink IR remotes can expose configured learned-code pairs as virtual Matter On/Off lights:

```json
{
  "broadlink_ir_mappings": {
    "aa:bb:cc:dd:ee:ff:2737": [
      {"id": "living-room-tv", "name": "Living Room TV", "on": "PASTE_ON_CODE_HEX", "off": "PASTE_OFF_CODE_HEX"}
    ]
  }
}
```

Replace both placeholder strings with the full hex payloads returned by IR learning for that remote; each payload must be non-empty valid hex. The mapping ID may contain ASCII letters, digits, `-`, and `_`. Matter reports the last successfully sent command as an estimate because IR devices do not provide state feedback. It cannot recover the real appliance state after restart, and the estimate remains unverified after each command. Codes stay in `config.json` and are not copied into the persistent device registry.

The JSON registry stores discovered device metadata and is atomically replaced with owner-only permissions on POSIX systems. It does not persist authentication tokens, session keys, or transient ONVIF service/profile caches, including values nested in protocol metadata; older entries are sanitized and rewritten at startup. eWeLink API keys, Xiaomi miIO tokens, ONVIF credentials, Broadlink IR mappings, and Matter commissioning identity belong in the private sibling `config.json`; Broadlink session keys are negotiated again on the LAN. eWeLink local control requires the device API key supplied in local configuration; Xiaomi control requires the device token. Broadlink devices use their local handshake. Broadlink and Xiaomi discovery send on each active IPv4 broadcast interface when the host exposes interface details. Only private or link-local unicast device addresses are accepted from discovery or registry data; loopback, multicast, unspecified, and globally routed addresses are discarded. Device discovery and control require the host and devices to share a LAN that permits broadcast traffic.

The app exposes a loopback HTTP API at `http://127.0.0.1:8765` (`GET /health`, `GET /api/devices`, `GET /api/devices/{brand}/{device_id}`, loopback-only `GET /api/devices/onvif/{device_id}/snapshot?profile={profile_token}`, loopback-only `POST /api/devices/onvif/{device_id}/sessions` for WebRTC negotiation, loopback-only `POST /api/camera-sessions/{session_id}/answer` and `/ice`, loopback-only `GET /api/camera-sessions/{session_id}` for worker status, loopback-only `DELETE /api/camera-sessions/{session_id}` to close, loopback-only `GET /api/devices/eseecloud/{device_id}/stream-info` for codec metadata, loopback-only `GET /api/devices/eseecloud/{device_id}/stream` for configured raw media, `PUT /api/devices/{brand}/{device_id}/state`, and Broadlink-only `POST /api/devices/broadlink/{device_id}/learn-ir`). The device list includes configured virtual Broadlink IR endpoints and the numeric `uiid` for eWeLink models when known. Health distinguishes API liveness (`ok`) from service readiness (`ready`), reports each adapter's running state and device count, and reports Matter as `starting`, `ready`, `unavailable`, `stopped`, or `disabled`. Matter startup and runtime exits are retried with backoff while LAN discovery and the API remain available. Normal LAN scans run every 60 seconds; empty scans and discovery transport errors use a bounded 5-to-60-second exponential retry. Commands are loopback-only by default. Set `api_host`, `api_port`, and `allow_remote_commands` in `config.json` only when appropriate for your network. For eWeLink B1 (UIID 22), the local state route accepts `{"hue":210,"saturation":80}` or `{"color_temp":235}` in mireds; L1 (UIID 59) accepts Hue/Saturation. These mappings follow an independent LAN integration and have not been validated against target captures or hardware.

Protocol `state.raw` remains available for diagnostics, but secret-looking fields such as keys, tokens, passwords, and credentials are recursively omitted from API JSON responses.

For a DUALR3 confirmed in motor mode, send `PUT /api/devices/ewelink/{device_id}/state` with `{"cover":{"direction":"open"}}`, `close`, or `stop`. The bridge rereads `workMode` under the per-device command lock before sending the corresponding local `motorTurn` command. Position targeting is not exposed until its local payload is validated.

Matter currently publishes On/Off endpoints for recognized plug/light types, configured Broadlink IR code pairs, separate On/Off endpoints for eWeLink relay channels when reported by the device, Level Control for dimmable lights, Extended Color Light endpoints with Hue/Saturation on eWeLink B1/L1 and Color Temperature on B1, temperature/humidity endpoints, contact sensors, PIR occupancy sensors, and a Lift-only Window Covering endpoint for DUALR3 motor mode. On/Off endpoints are created only after an actual boolean state is read, so a failed or not-yet-completed initial poll does not publish an invented `off` value; discovery synchronization retries endpoint creation after later state updates. Temperature and humidity endpoints are created only after a sample is within the Matter attribute range; an invalid or missing later sample leaves the last valid reading intact. Contact and occupancy endpoints are created only after the adapter reports an actual boolean sample, so an unknown initial reading is not advertised as closed or unoccupied. eWeLink TH10/TH16 models expose their relay as a plug and expose read-only temperature/humidity sensors only when the local `info` response contains numeric `params.currentTemperature`/`params.currentHumidity` values in range; those local fields still need packet-capture/hardware confirmation. The eWeLink DUALR3 (UIID 126) exposes independent relay endpoints only when the latest local state explicitly reports `params.workMode == 1` and its channel states; every relay command refreshes local state and requires an explicit channel. When local state reports motor mode (`workMode == 2`), it exposes a Matter Window Covering endpoint with open, close and stop commands mapped to the reported `motorTurn` protocol. Each motor command rechecks the mode while holding the per-device command lock. `currLocation` is returned as diagnostic state but is not used for Matter position control; percentage targeting and other work modes remain unsupported. These DUALR3 mappings are based on third-party command/state captures and still need confirmation with the target APK, firmware, packet captures and hardware. The eWeLink RF Bridge (UIID 28) is classified as an RF bridge and is not exposed as a plug; its paired RF child devices are not implemented. B1 color temperature is quantized to its inferred 2000/4250/6500 K modes. D1 (UIID 44) remains brightness-only. Thermostat setpoints are not mapped. Unknown or unsupported device types are omitted. `python-matter-server` is a controller, not an arbitrary bridged-endpoint publisher; the runtime uses matter.js dynamic endpoints. Apple Home and Google Home commissioning is the target, but still requires runtime and controller validation on the target LAN. matter.js is not CSA certified; this is an interoperability build, not a certification claim.

ONVIF-compatible cameras are inventoried through WS-Discovery; Yoosee/XM models may also appear through the cautious UDP probe described above. With per-camera credentials, the adapter reads capabilities, media profiles and RTSP URIs internally, polls advertised motion events using ONVIF PullPoint, exposes bounded PTZ move/stop commands, and serves JPEG snapshots through the loopback API. The API returns opaque profile selectors instead of RTSP URIs. Event topic variants and motion semantics still require camera validation. Local RTSP-to-WebRTC signaling and Matter camera allocation/provider endpoints are implemented for authenticated ONVIF profiles that advertise video and audio; controller and physical-camera interoperability still need validation. Some EseeCloud-compatible cameras also expose an independent HTTP `/livestream/{channel}` video source, documented by go2rtc; FIREALEXA exposes a configured source through the loopback raw-stream proxy documented above. EseeCloud devices still appear automatically only if they answer standard ONVIF discovery, and shared app branding does not prove protocol compatibility. Protocol research and remaining gaps are recorded in [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md).

Broadlink RM infrared data is sent as the learned buffer, without adding a second IR framing header. RM4 and new-firmware RM Mini models use the length-prefixed command envelope from [`python-broadlink`](https://github.com/mjg59/python-broadlink/blob/master/broadlink/remote.py); recognized RM4 models also poll the optional temperature/humidity sensor accessory and publish Matter sensor endpoints after numeric readings arrive. The A1 query byte and sensor offsets match the independent [`python-broadlink` A1 parser](https://github.com/mjg59/python-broadlink/blob/master/broadlink/sensor.py). These source comparisons corroborate protocol layout; captures from this bridge and hardware validation remain pending.

Broadlink SP2-compatible devices use the shared local power commands from [`python-broadlink`](https://github.com/mjg59/python-broadlink/blob/master/broadlink/switch.py). SP3 and SP3-EU preserve their separate nightlight bit during power writes; their Matter outlet endpoint reports only the power bit. SP3S variants use the shared SP2 power protocol. Energy readings and nightlight control are not exposed as Matter endpoints.

## Reverse-engineering evidence workflow (REA)

[REA (`morluto/rea`)](https://github.com/morluto/rea) is the reverse-engineering tool for APK evidence; it is not part of the bridge runtime. Follow its [official Android analysis guide](https://github.com/morluto/rea/blob/main/docs/android-analysis.md) and [installation guide](https://github.com/morluto/rea/blob/main/docs/installation.md): the launcher pins REA CLI 4.1.0, where the Android analysis family is available, and requires Node.js 22.23.4+, 24.22.1+, or 26.12.1+, a full JDK 17+, procps `ps`, and the pinned `jadx-headless-mcp` JAR with its SHA-256 verified. The local `tools/rea-android.sh` checks these prerequisites before launching REA:

Treat APKs as untrusted. Do not install third-party APKs on a personal device or execute them on the host. Use a disposable, isolated environment for JADX/REA: the APK is parser input and `npx` executes the REA npm package. A matching hash or valid APK signature checks identity/integrity only; it does not prove the APK is malware-free. See [APK handling precautions](REVERSE_ENGINEERING.md#untrusted-apk-handling) before analyzing an artifact.

```sh
export REA_JADX_MCP_JAR="$HOME/.local/share/rea/android/jadx-headless-mcp-0.7.1-all.jar"
tools/rea-android.sh inspect-android-package /absolute/path/app.apk
tools/rea-android.sh search-android-classes /absolute/path/app.apk zeroconf
tools/rea-android.sh inspect-android-method /absolute/path/app.apk example.DeviceClass methodName
```

Direct one-shot commands are also available after the pinned package and its dependencies have been staged in the npm cache. They are forced offline so they will not fetch executable code during APK analysis:

```sh
npx --offline --yes rea-agents@4.1.0 inspect-android-package /absolute/app.apk
npx --offline --yes rea-agents@4.1.0 search-android-classes /absolute/app.apk zeroconf
npx --offline --yes rea-agents@4.1.0 inspect-android-method /absolute/app.apk example.DeviceClass methodName
```

Check host prerequisites before downloading or analyzing an APK with `tools/rea-android.sh --preflight`; set `REA_JADX_MCP_JAR` to the pinned JAR first. This mode does not require an APK.

For each protocol claim, record APK digest, class/method or native symbol, source path/offset, packet-capture evidence, and what remains inferred before implementing writes.

## Camera media development

`matter_bridge/matter_node/camera-video.mjs` implements an internal
FFmpeg/RTP → WebRTC session using pinned `werift` 0.25.2. It transcodes to H.264
baseline level 3.1 at 640×360/30 fps and 600 kbit/s, starts the source after ICE/DTLS
connects, and stops the encoder, socket and peer when the session closes or expires.
The RTSP input helper accepts a URL only when it matches the discovered private
IPv4 address. Input URLs and FFmpeg stderr are not logged; however FFmpeg receives
the URL as a process argument, so credentials may be visible to local process
inspection. The helper validates the initial URL, not camera-issued RTSP redirects.

The local ONVIF API now uses this module through a private Node worker. With an
authenticated camera and a discovered profile from `GET /api/devices`, a local
WebRTC receiver can send an H.264-compatible SDP offer:

- `POST /api/devices/onvif/{device_id}/sessions` with JSON
  `{"profile":"PROFILE_TOKEN","sdp":"SDP_OFFER"}` returns `session_id`, `type`
  and the SDP answer. The answer includes gathered ICE candidates.
- To have the camera initiate negotiation, send only
  `{"profile":"PROFILE_TOKEN"}` to the same creation route. It returns
  `type: "offer"`; send the receiver's answer to
  `POST /api/camera-sessions/{session_id}/answer` with `{"sdp":"SDP_ANSWER"}`.
- `POST /api/camera-sessions/{session_id}/ice` with
  `{"candidate":{"candidate":"...","sdpMid":"0","sdpMLineIndex":0}}` forwards
  a receiver ICE candidate; `{"candidate":null}` marks completion.
- `GET /api/camera-sessions/{session_id}` reports whether the private media worker
  is still active; the Matter provider polls this to release stale stream allocations
  after a worker exits unexpectedly.
- `DELETE /api/camera-sessions/{session_id}` stops the session.

These routes require a loopback client and Host, same-origin browser requests,
and JSON for POSTs. Session IDs are private bearer handles: do not share them.
At most two sessions run at once. An unconnected session expires after 30 seconds;
a connected session expires after five minutes. No STUN/TURN server is configured.
Camera credentials are sent through worker stdin and are never returned by these
routes. Node 22.13+ and FFmpeg must be on the bridge process's PATH.

Profiles containing an ONVIF AudioEncoderConfiguration also offer one-way audio,
transcoded to stereo Opus at 48 kHz and 32 kbit/s. If the receiver declines audio,
only video is encoded. Profiles without advertised audio remain video-only.
Audio and video use one bundled ICE/DTLS transport. FFmpeg needs `libopus` as well
as `libx264` for audio sessions.

The media path still does not provide two-way talk or EseeCloud framed-media
demuxing. No physical camera or Matter controller has been validated with this
implementation.

Run the media tests with Node 22.13+ and FFmpeg with `libx264` on PATH:

```sh
cd matter_bridge/matter_node
node --test test/*.test.mjs
```

The integration cases generate synthetic video and a test tone, confirming H.264
and Opus RTP reach a second WebRTC peer with either peer initiating negotiation.
They also verify video continues when audio is declined and the process exits
after cleanup. It checks transport, not visual decoding,
physical camera behavior, or Matter controller interoperability.

The Matter AV allocation handlers are implemented and tested on an unstarted
local endpoint. Snapshot allocation/capture handlers now use the loopback ONVIF JPEG route
and resize to 640×360. Inputs are capped at 8 MiB and 16 megapixels; output is
capped at 256 KiB, with a ten-second conversion timeout. The tests also require
`ffprobe` to verify output dimensions. The running Matter bridge now publishes an
ONVIF Camera endpoint after authentication when a profile advertises both video
and audio. It uses an opaque profile selector, the existing bounded media worker,
snapshot conversion and WebRTC provider handlers. Root TLS management clusters,
a time client and a wired PowerSource component are composed into the node. The
root clock supports Matter UTC updates, NTP fallback, trusted Matter time sources
and time zone/DST commands. NTP and trusted-source polling start only when
configured by an administrator. That configuration is stored with the UTC
high-water mark in the Matter storage directory using an atomic private file.
The live UTC clock still starts unknown after restart and resynchronizes from the
saved source settings. Publication, streaming and callback delivery have not
been verified with a commissioned controller or the target camera. Passing
allocation/media checks is not Matter camera conformance.
