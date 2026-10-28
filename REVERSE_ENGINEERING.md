# Protocol reverse-engineering notes

## Untrusted APK handling

Treat every APK as untrusted input, including files labeled as coming from an
official store. Do not install it on a personal phone or run it on the host.
Prefer pulling the already-installed official app from a device you trust with
`tools/pull-android-apks.sh`; this copies APK splits and does not install or
launch them. For third-party downloads, first compare the SHA-256 and signing
certificate with a separately obtained, trusted official copy. `apksigner`
checks signature integrity only; a valid signature or matching hash is not a
malware scan.

Run JADX/REA in a disposable VM or container with no personal credentials,
limited filesystem access, and networking disabled after all required tools
have been staged and verified. JADX parses attacker-controlled ZIP/DEX/ELF
data, and the REA launcher executes the `rea-agents` npm package; pinning its
version does not establish that either parser or package is safe. Do not use
`npx -y` against an unknown registry mirror or let it fetch packages during the
isolated analysis. If the verified REA toolchain cannot be staged without
network access, stop before opening the APK and stage it through a reviewed,
trusted process first.

Use [REA](https://github.com/morluto/rea) for artifact-bound Android analysis. The launcher pins REA CLI 4.1.0, which includes the Android analysis family. Its supported Node.js ranges are 22.x 22.23.4+, 24.x 24.22.1+, or 26.12.1+ (including future majors after 26). Linux JADX also requires a full JDK 17+, `ps` from procps, and REA's pinned `jadx-headless-mcp` JAR. `tools/rea-android.sh` checks those prerequisites, the APK path, and the JAR digest before invoking the CLI. The JAR release and SHA-256 below are pinned by REA's [Android analysis guide](https://github.com/morluto/rea/blob/main/docs/android-analysis.md):

```sh
mkdir -p "$HOME/.local/share/rea/android"
cd "$HOME/.local/share/rea/android"
curl -fL -o jadx-headless-mcp-0.7.1-all.jar \
  https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar
echo '6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75  jadx-headless-mcp-0.7.1-all.jar' \
  | sha256sum -c -
export REA_JADX_MCP_JAR="$PWD/jadx-headless-mcp-0.7.1-all.jar"
```

Use REA's one-shot CLI commands without changing agent configuration after
the pinned package and dependencies have been staged into the npm cache. The
offline flag prevents npm from downloading executable code during analysis:

```sh
npx --offline --yes rea-agents@4.1.0 inspect-android-package /absolute/path/to/app.apk
npx --offline --yes rea-agents@4.1.0 search-android-classes /absolute/path/to/app.apk MainActivity
npx --offline --yes rea-agents@4.1.0 inspect-android-class /absolute/path/to/app.apk example.MainActivity
npx --offline --yes rea-agents@4.1.0 inspect-android-method /absolute/path/to/app.apk example.MainActivity onCreate
npx --offline --yes rea-agents@4.1.0 trace-android-references /absolute/path/to/app.apk example.MainActivity --method-name onCreate
```

Use the package inventory and class search to select a class, inspect its declared members, then inspect methods and references. For obfuscated releases, pass the matching `mapping.txt` with `--mapping-path` to class/method commands. Analyze native libraries and packet captures alongside Java call sites when JNI or sockets are involved. Record observations separately from derivations and inferences; keep the artifact digest, evidence path, method/symbol, offsets, capture timestamp, and unresolved questions next to each protocol fact. Never treat a class-name search as a search of method bodies or string constants.

Current host preflight: Node.js 22.22.0 is below REA's 22.x minimum. Java 25 runtimes and procps `ps` are present, but `javac` is absent, so this host does not currently have the required full JDK. `adb`, `apksigner`, the pinned JADX JAR, REA CLI cache, APKs, and packet captures are also absent. `tools/rea-android.sh` is the repeatable prerequisite gate; the Android CLI has not run in this workspace. The Matter bridge's own Node.js floor remains separately documented in `matter_node/package.json`.

When the apps are already installed on an authorized Android device, `tools/pull-android-apks.sh --out /tmp/firealexa-apks` copies every APK split for the five package IDs above without installing or launching them, and writes per-package SHA-256 manifests. It uses `apksigner` when available to verify APK signature integrity and record certificate digests; that does not by itself identify the publisher, so compare those digests with a trusted official copy. If `apksigner` is absent, capture metadata is marked `UNVERIFIED`. Treat third-party download-site malware scans as advisory, not proof of authenticity.

Do not treat inferred constants or generic vendor protocol descriptions as verified device behavior. Validate each adapter against packet captures and hardware before enabling writes. Never add account credentials, API keys, or unredacted tokens to source control.

### ONVIF PullPoint motion events

For cameras advertising an Events service, the adapter uses the standard `CreatePullPointSubscription` and `PullMessages` operations, then publishes an Occupancy Sensor endpoint only after a notification contains a `motion` topic and a recognized boolean `SimpleItem`. It omits a fixed initial termination time so regular `PullMessages` calls use the protocol's default keep-alive behavior; shutdown sends `Unsubscribe` with the returned WS-Addressing reference parameters. The ONVIF Core specification defines this pull-based event interface; topic names and boolean field meanings vary by camera, so the current parser is intentionally narrow and still needs per-model capture/hardware validation. Unsupported events do not create a Matter sensor. [ONVIF Core specification](https://www.onvif.org/specs/2412/ONVIF-Core-Spec-v2412.pdf)

Current code coverage: eWeLink mDNS plus encrypted HTTP commands; Broadlink UDP discovery/auth/control, loopback-only IR learn API, IR send/learn payloads, and configured virtual On/Off mappings for learned IR code pairs; Xiaomi miIO hello discovery (three HELLO broadcasts per interface, matching the upstream client retry count) and token-authenticated `miIO.info`, `get_prop(power)`, and `set_power`; ONVIF WS-Discovery plus an inferred Yoosee/XM UDP candidate probe, configurable WS-Security UsernameToken/HTTP Digest authentication, capabilities/profile/RTSP URI reads, Events PullPoint motion notifications, bounded PTZ move/stop API, and loopback-only authenticated JPEG snapshot retrieval; matter.js bridge endpoints for on/off, reported eWeLink relay channels, DUALR3 Lift-only Window Covering open/close/stop, dimmable-light Level Control, B1/L1 color control, temperature, humidity, contact, ONVIF motion events, and PIR occupancy state shapes. B1 (UIID 22) and L1 (UIID 59) now use Extended Color Light endpoints; Matter Hue/Saturation commands map to eWeLink local payloads and B1 exposes color-temperature commands, quantized to 2000/4250/6500 K. The mapping is grounded in an independent LAN integration, not target APKs or captures, and remains unverified against firmware variants. DUALR3 (UIID 126) is exposed as independent relay endpoints only when local state reports `params.workMode == 1` and channel states; before each relay write the adapter refreshes local state, requires the same relay mode and an explicit valid channel, and refuses aggregate writes. In motor mode (`workMode == 2`), a Lift-only Window Covering endpoint maps open/close/stop to `motorTurn` values 1/2/0. Each command checks the current mode in the same per-device command lock as the network write. `currLocation` is parsed and returned through the local API for diagnostics but is not used for Matter position control; other work modes remain unsupported. These command mappings come from third-party app/device logs, not the target APK or this bridge's captures, and require hardware validation. Broadlink virtual IR state records the last successfully sent command and is not device feedback. eWeLink TH10/TH16 conditionally reads `params.currentTemperature` and `params.currentHumidity` from local `info` replies and exposes the relay plus read-only sensor endpoints. Those field names also appear in a cloud-oriented eWeLink SDK, which is not evidence that Zeroconf returns them; this mapping remains a hypothesis until a local capture/hardware check confirms it. Thermostat setpoints are not mapped. ONVIF event topics and motion semantics still need per-model validation. Missing: a validated Yoosee/XM response parser, EseeCloud model/firmware validation, RTSP/EseeCloud-to-WebRTC translation and Matter camera endpoints, verified packet captures/hardware validation, additional Matter device types, and end-to-end controller commissioning. Xiaomi tokens must be supplied locally; discovery does not recover provisioned tokens. Xiaomi control assumptions still need confirmation against device captures and hardware.

### eWeLink B1, D1 and L1 light payloads

The independent [SonoffLAN light adapter](https://github.com/AlexxIT/SonoffLAN/blob/master/custom_components/sonoff/light.py) distinguishes the relevant local `dimmable` payloads by UIID: B1 (22) uses `zyx_mode` and `channel0..channel4` for white-temperature/RGB modes; D1 (44) exposes `switch` and `brightness`; L1 (59) uses `bright`, `colorR/G/B`, `mode`, and `light_type`. The bridge classifies D1 as brightness-only, maps B1 white temperature to its three inferred Kelvin buckets, and sends color writes for B1/L1 through the existing encrypted `zeroconf/dimmable` request. The Matter runtime exposes B1/L1 ColorControl feature variants and routes hue/saturation MoveTo, Move, and Step logic to the local API; B1 also maps color-temperature MoveTo, Move, and Step operations, with 300 ms LAN updates during continuous movement. The field mapping is reference-code corroboration only: the target APK, exact light firmware, packet captures, matter.js runtime, and controller interoperability have not been validated.

### Broadlink A1 protocol evidence

The Broadlink A1 query and parser currently match the independent LAN implementation in [`python-broadlink/broadlink/sensor.py`](https://github.com/mjg59/python-broadlink/blob/master/broadlink/sensor.py): command byte `0x01`, temperature at decrypted offsets `0x04`/`0x05` in tenths, humidity at `0x06`/`0x07` in tenths, and raw light/air-quality/noise at `0x08`/`0x0A`/`0x0C`. The adapter preserves those bytes and adds the documented ordinal labels (`dark`/`dim`/`normal`/`bright`, `excellent`/`good`/`normal`/`bad`, and `quiet`/`normal`/`noisy`) to `state.raw` for the local API. Out-of-range byte values retain their raw integer and get a `null` label. These categories are not physical lux, pollutant concentration, or decibels; they are not published as Matter measurement endpoints. This independently corroborates the adapter's implementation, but is not a capture from a device running this bridge. Local hardware/capture validation remains outstanding.

### Broadlink discovery response validation

The upstream [`python-broadlink` scanner](https://github.com/mjg59/python-broadlink/blob/master/broadlink/device.py) reads the response devtype at `0x34`, reversed MAC bytes at `0x3a:0x40`, UTF-8 name at `0x40` through NUL, and lock status at `0x7f`. The bridge now requires the response to reach `0x7f`, accepts only LAN-unicast sources and unicast nonzero MACs, and bounds the name to its fixed field before the lock byte. This guards malformed discovery datagrams; it does not authenticate a device identity.

### Broadlink RM command-envelope evidence

The [`python-broadlink` remote implementation](https://github.com/mjg59/python-broadlink/blob/master/broadlink/remote.py) confirms two command encodings: legacy RM uses a four-byte little-endian command followed by data; `rmminib`/RM4 uses a little-endian two-byte length and four-byte command before the data, and its response strips that six-byte envelope. The adapter now uses the correct envelope for known RM4 and new-firmware RM Mini IDs. Learned IR responses already contain the IR data header, so sending them verbatim avoids adding a duplicate header. The same upstream source defines RM4 sensor query `0x24` and its temperature/humidity byte layout; these readings are published only as numeric sensor state. These mappings are source corroborated, not hardware verified.

The upstream [`python-broadlink` type map and switch implementation](https://github.com/mjg59/python-broadlink/blob/master/broadlink/switch.py) identify SP2-compatible models that share power commands and SP3/SP3-EU models whose power and nightlight state occupy separate bits in one byte. Discovery now recognizes those protocol families, reads the SP3 power bit independently, and preserves the nightlight bit on writes. SP3S shares the SP2 power methods. This does not implement energy reporting or independent nightlight control.

### Yoosee/XM discovery fallback (unverified against target hardware)

Third-party model-specific research reports a Yoosee/XM LAN setup with UDP discovery on port `8899`, RTSP on `554` at `/onvif1`, and ONVIF/SOAP on TCP `5000`. It gives a 28-byte discovery probe (`70021c000000000000000000737f759d00000000000001020a00c422`) and the ONVIF profile token `IPCProfilesToken0`. The same report says its attempted XM/TCP login format did not work. The adapter now sends that probe as a discovery lead and uses the probe's `70 02` prefix as a weak heuristic for candidate replies; it also requires TCP `5000` and `554` to accept connections before creating an unauthenticated camera record. The response signature and parser are not validated. Standard ONVIF credentials and service/profile discovery remain required for control and stream metadata. Treat these details as leads for the camera model used in that research only: the document does not establish that the bytes, credentials, RTSP path, or ONVIF endpoints apply across Yoosee firmware or EseeCloud cameras. See the [Yoosee camera research notes](https://github.com/victorbillyph/Yoosee-camera-documentation/blob/main/README.md) and the separate [Yoosee Home Assistant integration](https://github.com/victorbillyph/Yoosee-hacs-integration), which scopes support to cameras exposing ONVIF on `5000` and RTSP on `554`.

No Yoosee/XM or EseeCloud packet has been captured from a target device in this workspace. The XM fallback is inference from third-party documentation and the binary response parser remains unknown. Generic ONVIF PTZ is exposed only when a camera's configured credentials authenticate and its ONVIF profile advertises PTZ; hardware behavior still needs confirmation. A local video path is now identified for one EseeCloud-compatible camera family: go2rtc documents HTTP `livestream/{channel}` sources, such as channels 11/12, and its parser reads an HTTP preamble followed by `$`-framed packets carrying an RTP-like packet with codec metadata. This establishes a local video transport for those models, not a common EseeCloud discovery, control, or authentication protocol. FIREALEXA can proxy a manually configured source, but does not decode it or provide RTSP/EseeCloud-to-WebRTC translation, Matter camera endpoints or ecosystem commissioning; exact camera models, credentials, stream channels and firmware still need confirmation.

Evidence: the [go2rtc EseeCloud source documentation](https://github.com/AlexxIT/go2rtc/blob/master/internal/eseecloud/README.md) limits the source to cameras with an HTTP `/livestream/{channel}` URL. Its [open-source packet parser](https://github.com/AlexxIT/go2rtc/blob/master/pkg/eseecloud/eseecloud.go) consumes an HTTP response preamble, parses announced H.264/H.265 and G.711 formats, then reads `$`-prefixed packets whose payload length is a big-endian uint32 at bytes 4–7. The associated [go2rtc issue](https://github.com/AlexxIT/go2rtc/issues/1690) documents successful local access with HTTP Basic authentication and notes H.265 browser compatibility constraints. This is independent implementation evidence, not an APK analysis or a capture from the user's camera.

FIREALEXA now supports a manually configured EseeCloud-compatible source (`eseecloud_streams`), a loopback-only codec metadata probe at `/api/devices/eseecloud/{device_id}/stream-info`, and a loopback-only raw media proxy at `/api/devices/eseecloud/{device_id}/stream`. Configuration pins an IPv4 private/link-local address, port, channel and optional Basic credentials; the adapter builds the `/livestream/{channel}` path itself, refuses redirects, and does not persist credentials in the device registry. The proxy validates the H.264/H.265 preamble and `$` frame lengths (up to 4 MiB), then passes the framed media through without decoding or translating transport. It limits each camera to two concurrent viewers. It does not create a Matter camera endpoint, and a successful HTTP response is only evidence that this configured stream path is reachable.

### DUALR3 motor-mode evidence (inferred; hardware validation pending)

Third-party DUALR3 logs show `params.workMode`, `currLocation`, `location`, and `motorTurn`; the published LAN command traces send `/zeroconf/motorTurn` with `{"motorTurn":1}` for open, `0` for stop, and `2` for close, receiving `error:0` acknowledgements. A separate report tried `{"pulses":{"location":50}}` and received `error:400`; that is evidence this particular command path is invalid, not evidence that all local position commands fail. Sonoff's product guide says a calibrated DUALR3 supports specific-position control from the eWeLink app, but it does not document a local Zeroconf endpoint or payload. The adapter therefore parses the reported position only for diagnostics and does not expose Matter percentage targeting. It sends directional commands only after a fresh `info` read confirms `workMode == 2`, with both operations serialized by the per-device command lock. These are community captures and product documentation from other devices/firmware, not captures from the target APK or this workspace. See the [DUALR3 LAN command traces](https://community.jeedom.com/t/sonoff-dual-r3-volets-roulants/93294), [reported DUALR3 motor state](https://github.com/AlexxIT/SonoffLAN/issues/1066), and [Sonoff motor-mode guide](https://www.sonoff.in/blog/product-guides-3/insights-into-dualr3-s-three-working-modes-switch-motor-and-meter-modes-103).

### ONVIF authentication and PTZ implementation

The generic camera adapter follows ONVIF's WS-UsernameToken `PasswordDigest` construction (base64 of SHA-1 over decoded nonce, UTC creation time and password), with HTTP Digest as a fallback when the service returns a Digest challenge. It calls `GetCapabilities`, `GetProfiles` and `GetStreamUri`; XAddrs and RTSP URIs are accepted only when their host is the camera's discovered source IP. PTZ is enabled only for a profile containing `PTZConfiguration`; moves use `ContinuousMove` with a bounded timeout followed by `Stop`. These operation and authentication shapes follow the [ONVIF Application Programmers Guide](https://www.onvif.org/wp-content/uploads/2016/12/ONVIF_WG-APG-Application_Programmers_Guide-1.pdf), [ONVIF Profile S authentication requirements](https://www.onvif.org/wp-content/uploads/2017/01/ONVIF_Profile_-S_Specification_v1-1-1.pdf), and [ONVIF PTZ specification](https://github.com/onvif/specs/blob/development/doc/PTZ.xml). This is spec-based implementation evidence, not confirmation against a Yoosee/EseeCloud camera. RTSP media transport and Matter camera/WebRTC remain separate unimplemented work.

### Matter camera implementation boundary

Matter 1.5 camera interoperability uses the Camera AV Stream Management cluster
for stream allocation and the WebRTC Transport Provider cluster for SDP/ICE
signaling; camera video/audio travels over the negotiated WebRTC session. The
[CSA Matter 1.5 announcement](https://csa-iot.org/newsroom/matter-1-5-introduces-cameras-closures-and-enhanced-energy-management-capabilities/)
describes WebRTC as the camera media transport, and the reference
[`connectedhomeip` device model](https://github.com/project-chip/connectedhomeip/blob/master/src/app/zap-templates/zcl/data-model/chip/matter-devices.xml)
lists both clusters for the Camera device type. Accordingly, FIREALEXA's
ONVIF RTSP URI and EseeCloud raw framed HTTP proxy are upstream source inputs,
not Matter camera endpoints. Completing that path requires a WebRTC media
gateway that can consume those source formats, allocate/report stream
capabilities, answer Matter offers, exchange ICE candidates, handle session
cleanup, and expose the required Matter cluster behaviors. A snapshot-only or
motion-only endpoint cannot stand in for live camera support. Validate the
result against Matter controller interoperability and the target camera
firmware before claiming Apple Home or Google Home camera support.

An implementation reference is available in
[Matterbridge's camera documentation](https://matterbridge.io/Camera.html): it
uses `werift` for the WebRTC peer connection and `ffmpeg` for media input and
encoding. Its 3.10.14 release added a network-camera plugin for RTSP sources;
the plugin requires an RTSP URL and does not discover cameras. This is a
reference implementation, not a drop-in library for FIREALEXA: this project
currently runs its own `@matter/main` `ServerNode`, and a separate Matterbridge
process would create another Matter node and commissioning identity. The
workspace has system `ffmpeg`, but no installed `werift`, Matterbridge, or
Matter Node runtime dependencies. For ONVIF cameras, the shortest integration
path is RTSP input to a local WebRTC source while keeping ONVIF credentials
inside the backend. EseeCloud's framed HTTP/RTP-like source needs demuxing or
conversion before it can enter that same media pipeline. See the
[Matterbridge camera release notes](https://github.com/Luligu/matterbridge/releases)
and [camera signaling guide](https://matterbridge.io/Camera.html) for the
reference media/session flow.
