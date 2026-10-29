# Protocol reverse-engineering notes

## Untrusted APK handling

`tools/rea-isolated.sh` provides a static Android analysis launcher for a
locally staged Docker image identified by its immutable `sha256:` image ID.
It disables networking, runs as an unprivileged user, drops capabilities,
limits memory/processes/CPU, and exposes only the selected APK as a read-only
bind mount. The image must already contain the reviewed offline REA CLI,
Java and pinned JADX JAR at the paths documented in the script. It never
pulls an image or installs tools. On macOS this requires a running Linux VM
provided by the container runtime. The `firealexa-re` Colima VM is now running (Linux aarch64, Docker
29.5.2), with 2 CPUs, 4 GiB RAM and a 20 GiB data disk. Its only host
share is `/private/tmp/firealexa-apks`, read-only; SSH agent forwarding is
disabled. Use `DOCKER_CONTEXT=colima-firealexa-re` with the launcher.
The image built from `tools/rea.Dockerfile` is
`sha256:0dbb770f33918c06c3640ad5a504fe52191ab5511b45d37b5f7243b7b090a829`.
An isolated `inspect-android-package` run completed successfully against
XMEye 6.6.4, reporting package `com.mobile.myeye`, version code 66400,
33 classes and 3847 resources. This verifies the offline launcher/REA/JADX
path, not APK authenticity or camera functionality. Signature verification
was not performed. The build pins the base image and REA version, disables
npm lifecycle scripts and verifies the JADX hash; transitive npm and Debian
packages are resolved at build time, so a future rebuild may differ.
The host's existing Docker credential helper is missing; the successful run
used `DOCKER_CONFIG=/private/tmp/firealexa-docker-config` (empty config) and
`DOCKER_HOST=unix:///Users/macbookair/.colima/firealexa-re/docker.sock` instead
of the context. Stage only the Dockerfile and verified JAR in the build
context; never include APKs or credentials in it. This launcher does not retroactively isolate earlier analyses.

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

Current host preflight: macOS, Node.js 24.14.1 and a full Temurin JDK 24 are available. The pinned JADX 0.7.1 JAR (SHA-256 `6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75`) and REA CLI 4.1.0 were staged in `/private/tmp/firealexa-apks` and the npm cache. `adb` and `apksigner` are absent. APKPure EseeCloud, Yoosee and XMEye packages were analyzed without installation or execution. Whole-package EseeCloud and Yoosee loading exceeded the standard 512 MiB heap, so analysis used temporary single-DEX APK slices containing original DEX bytes plus each original manifest. A temporary REA copy raised the JADX heap to 2 GiB for targeted class/method analysis; its evidence metadata was patched to report that limit. REA's process cleanup needs permission to inspect the host process table on this macOS environment. At the time of those analyses no disposable VM/container was available, and some REA calls ran outside the workspace sandbox so the process tree could be inspected; this was static parsing only, but it is not a hardened isolated analysis environment. The APKs were never installed or launched. Artifact hashes and slice provenance are recorded below. No packet capture or target-device response is available. The Matter bridge's own Node.js floor remains separately documented in `matter_node/package.json`.

When the apps are already installed on an authorized Android device, `tools/pull-android-apks.sh --out /tmp/firealexa-apks` copies every APK split for the five package IDs above without installing or launching them, and writes per-package SHA-256 manifests. It uses `apksigner` when available to verify APK signature integrity and record certificate digests; that does not by itself identify the publisher, so compare those digests with a trusted official copy. If `apksigner` is absent, capture metadata is marked `UNVERIFIED`. Treat third-party download-site malware scans as advisory, not proof of authenticity.

Do not treat inferred constants or generic vendor protocol descriptions as verified device behavior. Validate each adapter against packet captures and hardware before enabling writes. Never add account credentials, API keys, or unredacted tokens to source control.

### ONVIF PullPoint motion events

For cameras advertising an Events service, the adapter uses the standard `CreatePullPointSubscription` and `PullMessages` operations, then publishes an Occupancy Sensor endpoint only after a notification contains a `motion` topic and a recognized boolean `SimpleItem`. It omits a fixed initial termination time so regular `PullMessages` calls use the protocol's default keep-alive behavior; shutdown sends `Unsubscribe` with the returned WS-Addressing reference parameters. The ONVIF Core specification defines this pull-based event interface; topic names and boolean field meanings vary by camera, so the current parser is intentionally narrow and still needs per-model capture/hardware validation. Unsupported events do not create a Matter sensor. [ONVIF Core specification](https://www.onvif.org/specs/2412/ONVIF-Core-Spec-v2412.pdf)

Current code coverage: eWeLink mDNS plus encrypted HTTP commands; Broadlink UDP discovery/auth/control, loopback-only IR learn API, IR send/learn payloads, and configured virtual On/Off mappings for learned IR code pairs; Xiaomi miIO hello discovery (three HELLO broadcasts per interface, matching the upstream client retry count) and token-authenticated `miIO.info`, `get_prop(power)`, and `set_power`; ONVIF WS-Discovery plus an inferred Yoosee/XM UDP candidate probe, configurable WS-Security UsernameToken/HTTP Digest authentication, capabilities/profile/RTSP URI reads, Events PullPoint motion notifications, bounded PTZ move/stop API, and loopback-only authenticated JPEG snapshot retrieval; matter.js bridge endpoints for on/off, reported eWeLink relay channels, DUALR3 Lift-only Window Covering open/close/stop, dimmable-light Level Control, B1/L1 color control, temperature, humidity, contact, ONVIF motion events, PIR occupancy state shapes, and an authenticated ONVIF camera path with bounded RTSP-to-WebRTC media, snapshot and Matter camera/provider handlers. Camera UTC/time settings persist locally with restrictive permissions and restart in an unsynchronized state. B1 (UIID 22) and L1 (UIID 59) now use Extended Color Light endpoints; Matter Hue/Saturation commands map to eWeLink local payloads and B1 exposes color-temperature commands, quantized to 2000/4250/6500 K. The mapping is grounded in an independent LAN integration, not target APKs or captures, and remains unverified against firmware variants. DUALR3 (UIID 126) is exposed as independent relay endpoints only when local state reports `params.workMode == 1` and channel states; before each relay write the adapter refreshes local state, requires the same relay mode and an explicit valid channel, and refuses aggregate writes. In motor mode (`workMode == 2`), a Lift-only Window Covering endpoint maps open/close/stop to `motorTurn` values 1/2/0. Each command checks the current mode in the same per-device command lock as the network write. `currLocation` is parsed and returned through the local API for diagnostics but is not used for Matter position control; other work modes remain unsupported. These command mappings come from third-party app/device logs, not the target APK or this bridge's captures, and require hardware validation. Broadlink virtual IR state records the last successfully sent command and is not device feedback. eWeLink TH10/TH16 conditionally reads `params.currentTemperature` and `params.currentHumidity` from local `info` replies and exposes the relay plus read-only sensor endpoints. Those field names also appear in a cloud-oriented eWeLink SDK, which is not evidence that Zeroconf returns them; this mapping remains a hypothesis until a local capture/hardware check confirms it. Thermostat setpoints are not mapped. ONVIF event topics and motion semantics still need per-model validation. Missing: validated Yoosee/XM discovery parsing, Yoosee P2P/NVR configuration in the bridge, EseeCloud model/firmware validation, verified packet captures and hardware/controller validation, additional Matter device types, and robust Matter edge-case/interoperability coverage. Xiaomi tokens must be supplied locally; discovery does not recover provisioned tokens. Xiaomi control assumptions still need confirmation against device captures and hardware.

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

### EseeCloud Android NVR discovery (static REA evidence; not the camera RTSP setting)

The EseeCloud `com.juanvision.eseecloud30` XAPK 4.14.0.4 was downloaded from APKPure to `/private/tmp/firealexa-apks/eseecloud.xapk` (XAPK SHA-256 `27a528394ff80446cb9da422a082f345f5959a66256fd0ef17f2b9dc0b7b726e`). Its extracted base APK SHA-256 is `032b936fddfef856c13ad38274c8f4e9c80e69f34acc5e70a80b74ef7453d431`; package metadata reports version code `41400041`. APK signature verification was not performed. The APK was not installed or executed.

Because whole-package REA/JADX loading hit Java heap exhaustion at an observed 512 MiB, REA 4.1.0 with the pinned JADX 0.7.1 engine analyzed temporary APK slices built from the unmodified DEX bytes and original manifest. For the current app, the relevant source is `classes11.dex`, SHA-256 `f388137519d39f9f72dca65ce4e3a668697fb36bc46c22352ebabdde5c89fc98`; its slice is `/private/tmp/firealexa-apks/current-dex-slices/classes11.apk`. The original APK digest above remains the parent artifact identity; a slice is a derived analysis container, not an installable or authentic APK.

Observed in `AddTableNVRDeviceActivity.initData` and `execTask`: the screen creates `TaskScanLanDevice`, then calls `mLanNVRTask.exec(1000L, null, false, false, true)`. `TaskScanLanDevice.onTaskInit` maps those booleans to common discovery, old NVR discovery, and new NVR discovery respectively, so this screen enables only the new NVR branch. `sendDiscoverProtocol` builds the type-100 request through `NVRProtocolUtil.getString`; `getWifiScanDeviceInfo(int)` formats it as:

```text
SEARCH * HDS/1.1\r\n
CSeq:<sequence>\r\n
Client-ID:CeCOlDpmTuzViBQDgbrPgFkfnyyzNabc\r\n
Accept-Type:text/HDP\r\n
Content-Length:13\r\n
X-Search-Type:NVR\r\n
{"Ver":"1.1"}
```

`startSendDiscoverProtocol` sends this request through `MulticastHelper.postData` to `NVR_PORT`, increments the sequence on each new-NVR scan, and sleeps 3 seconds between scans when this screen's flags are used. `onMultiCastCallback` parses a response from its first `{` as `NVRResponseInfo`; `handleNewNVRData` completes discovery only when `eseeId` is non-empty. The response model also exposes `deviceId`, `deviceType`, `deviceModel`, `channelCount`, `softwareVersion`, `ver`, `nonce`, `capabilities` and `wired` fields. `MulticastHelper` sends UDP datagrams to `BROADCAST_ADDR`; exact `NVR_PORT`, `BROADCAST_ADDR`, and response source behavior still need extraction or capture confirmation.

The app also contains a legacy parser branch: `handleOldNVRData` accepts text beginning `JA`, splits subsequent `&`-separated fields, and recognizes `IP`, `ID`, `PORT`, `HTTP`, `CH`, `MODEL` and `PVER`. The NVR screen analyzed above passes `mScanOldNVR=false`, so this legacy branch is not used in that flow.

These methods establish a proprietary LAN NVR discovery path in the Android app. They do not establish that the user's `NVR Connection` toggle uses this protocol, provide a camera RTSP URI/password, or reveal camera-setting commands. The screenshot says third-party NVR/CMS/ONVIF apps can connect on the same LAN and that RTSP needs a separately configured security password. That is consistent with an RTSP/ONVIF server feature, but its enable/configuration request remains untraced. No packet from the target camera has been captured.

### Yoosee NVR connection and RTSP configuration (static REA evidence)

APKPure's Yoosee 6.46.1 XAPK (`com.yoosee`, version code 6454) was staged at `/private/tmp/firealexa-apks/yoosee-latest.xapk`, SHA-256 `d46578fb6a47b1e7fdd6f0c9cf87fd500fcb4daeb5b6c99b70d1c4b95c19dfad`. Its base APK is `/private/tmp/firealexa-apks/yoosee-6.46.1.apk`, SHA-256 `1c3b3aef5ed6f1d8ca791fd6094be6881994e6d580edee44ba8930299d4f4387`. Signature verification was not performed. REA/JADX 0.7.1 analyzed derived `classes8.dex` and `classes9.dex`/`classes10.dex` slices with SHA-256 `71d3809c43c90186ffec837944dbe3e484c86816305745e0b360b40b3a3519a6`, `72d0b4fc9087c90518b1792243763be072dadbbc58e545c73c3c03b3981f1529` and `ebfc82fa63e658a5ee3522166df9252bbac096270789a7aaeaa7b4ad33bd6f3a`; these retain original DEX bytes and the original manifest, and are analysis containers only.

In `ConnectNVRNewFragment.initView`, the screen reads the current connection state using `od.b.U().t1(contactId)` and checks whether RTSP account editing is supported with `od.b.U().d2(contactId, DevFunCode.FunCode.RTSP_NAME_MODIFY)`. It initializes `switchRtsp` from that state and attaches `ConnectNVRNewFragment.b`. The listener methods `toggleToOn` and `toggleToOff` call `ConnectNVRViewModel.openRTSP(true)` and `openRTSP(false)`. In `ConnectNVRViewModel.openRTSP(boolean)`, the app calls `h.b().L(contactId, "1" or "0", callback)`; the owner/transport behind `h.b().L` remains unresolved. If account support is present, `ConnectNVRNewFragment.initData` requests RTSP data with `getRTSPInfo()`.

`ConnectNVRViewModel.getRTSPInfo` calls `IDevIotPenetrateApi.getRTSPInfo`. `DevIotPenetrateApiImpl` serializes `PenetrateBase(42)` and passes the bytes to `sendPenetrateImpl`. Its response parser requires `PenetrateRTSPInfoResult.type == 42`; the response model has `data.code` and `data.accountPwd`. `ConnectNVRViewModel.setRTSPInfo(account, password)` combines the values through `k0.a.b(contactId, account, password)`, puts the result in `PenetrateRTSPInfo(43).data.accountPwd`, serializes it as JSON and sends it. `setRTSPpwd(password)` derives bytes with `IoTVideoInitializer.getP2pAlgorithm().getRtspPassword(NVR_PWD_BEGIN + password)`, converts those bytes to a string, places it in `PenetrateRTSPPwd(3).data.pwd`, and sends it. The JADX source for `ConnectNVRViewModel` in Yoosee 6.46.1 `classes8.dex` resolves `NVR_PWD_BEGIN` to `"admin:HIipCamera:"`. The JNI function returns lowercase MD5 hex, so the supplied password text is transformed as `MD5("admin:HIipCamera:" + password)` and sent in the type-3 payload. `P2PAlgorithmProxy.getRtspPassword` delegates to JNI `nGetRtspPassword`; exported symbol `Java_com_jwkj_iotvideo_kits_P2PAlgorithmProxy_nGetRtspPassword` is present at ELF address `0x1a5220` in arm64 `libiotvideomulti.so` (SHA-256 `3f60694166a5c987e508e7ac7adda6f06050989bc802ffed5083514f836a0e54`). Static disassembly of `iv_get_rstp_password` shows `mbedtls_md5(input)`, a `%02x` conversion for each digest byte, and a 32-byte ASCII-hex output. The `k0.a.b` account/password encoding and `h.b().L` toggle transport remain unresolved; neither has been validated against a camera.

`sendPenetrateImpl` rejects devices in battery-drain mode, converts the JSON to bytes and calls `MessageMgr.sendMsgToDevice`. `MessageMgrInternal` routes that to native `nSendMsgToDevice` using `MessageDomain.USER`, `BuiltInCmd.INVALID`, timeout `0`, and the response flags supplied by each operation. This establishes a device-targeted message through the app's native IoT/P2P message stack; it is not evidence of a direct HTTP/UDP command to the camera's LAN IP. These packet type values and structures are Yoosee app evidence and must not be copied into an EseeCloud adapter without matching firmware evidence.

The decompiled RTSP methods also pass derived password text, the combined `accountPwd` string and serialized JSON to the app's logging calls. This is a credential-exposure risk if those log calls are enabled or collected; no device values or credentials were present in this analysis. The screenshot's wording and package provenance have not been independently matched to Yoosee, so this is a strong protocol lead rather than proof that the pictured camera is running Yoosee-compatible firmware. No device exchange, credentials, or resulting RTSP URI have been captured.

### XMEye native camera SDK (static REA/artifact evidence)

The APKPure XMEye 6.6.4 APK (`com.mobile.myeye`, version code 66400) is at `/private/tmp/firealexa-apks/xmeye-6.6.4.apk`, SHA-256 `7371ee4ad5149f803c2173bbb216b1582d094fc316996b930c235fee267b4734`. REA's JADX provider reports only 33 Java classes, predominantly from the Netease wrapper/loader family; the app's business implementation is not available through that DEX class inventory. Its arm64 native `libFunSDK.so` was extracted without loading or executing it, SHA-256 `b77e560523849862f8998f7c67187f4bdc519e3e868fd822d921976092bb65b5`; REA's safe artifact provider identifies it as a 24,646,120-byte ELF shared library.

Static native symbol strings include `H264_DVR_SearchDevice`, `FUN_DevSearchDevice`, `FUN_DevSetNetCfgOverUDP`, `CDataCenter::SearchDevices`, and RTSP client entry points for `OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY`, `PAUSE` and `TEARDOWN`. This confirms the packaged SDK contains device discovery/configuration and RTSP-client code paths, but stripped/native symbol names do not reveal packet layouts or prove the camera's RTSP server settings. XMEye remains a separate vendor stack from Yoosee and EseeCloud; no model or firmware match has been established.

### ONVIF authentication and PTZ implementation

The generic camera adapter follows ONVIF's WS-UsernameToken `PasswordDigest` construction (base64 of SHA-1 over decoded nonce, UTC creation time and password), with HTTP Digest as a fallback when the service returns a Digest challenge. It calls `GetCapabilities`, `GetProfiles` and `GetStreamUri`; XAddrs and RTSP URIs are accepted only when their host is the camera's discovered source IP. PTZ is enabled only for a profile containing `PTZConfiguration`; moves use `ContinuousMove` with a bounded timeout followed by `Stop`. These operation and authentication shapes follow the [ONVIF Application Programmers Guide](https://www.onvif.org/wp-content/uploads/2016/12/ONVIF_WG-APG-Application_Programmers_Guide-1.pdf), [ONVIF Profile S authentication requirements](https://www.onvif.org/wp-content/uploads/2017/01/ONVIF_Profile_-S_Specification_v1-1-1.pdf), and [ONVIF PTZ specification](https://github.com/onvif/specs/blob/development/doc/PTZ.xml). The RTSP media, snapshot and Matter camera/provider path is now implemented for authenticated ONVIF profiles; see the implementation sections below. This remains spec-based implementation evidence and has not been confirmed against a Yoosee/EseeCloud camera or a commissioned Matter controller.

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
workspace has system `ffmpeg` and installed `@matter/main` 0.18.0
dependencies (recorded in `matter_node/package-lock.json`), with `werift` 0.25.2 now installed; Matterbridge is not installed. Importing `@matter/main` with Node 24.14.1 succeeds
outside the macOS sandbox; the sandbox denies the library's `os.uptime()` call.
The installed camera and WebRTC server classes are generated behavior
skeletons, not an implemented media gateway. For ONVIF cameras, the shortest integration
path is RTSP input to a local WebRTC source while keeping ONVIF credentials
inside the backend. EseeCloud's framed HTTP/RTP-like source needs demuxing or
conversion before it can enter that same media pipeline. See the
[Matterbridge camera release notes](https://github.com/Luligu/matterbridge/releases)
and [camera signaling guide](https://matterbridge.io/Camera.html) for the
reference media/session flow.


### RTSP-to-WebRTC media transport

`camera-video.mjs` now provides a bounded video session using FFmpeg H.264 RTP
and werift 0.25.2. A local synthetic-source integration test passes: at least ten
nonempty RTP payloads arrive at a second WebRTC peer after offer/answer and
ICE/DTLS negotiation. Separate checks cover private-IP source matching,
oversized SDP rejection and unsupported video codec rejection. Closing the
session is idempotent. This is transport evidence only: no camera RTSP exchange,
visual decoding, audio, Matter stream allocation or controller test has occurred.
The local API now connects the ONVIF adapter to this session via a private
newline-delimited JSON subprocess channel. The adapter rechecks authentication,
profile identity and URI host before attaching URL-encoded configured credentials.
Only SDP, ICE and opaque session IDs cross the HTTP API. The Python manager limits
concurrent workers to two and closes them at API shutdown. A real Python-to-Node
IPC check passed negotiation, two-session capacity, ICE completion and worker
shutdown without supplying the answer to a receiver (so no camera was contacted).
Five Node media tests and 26 Python tests passed at this implementation stage.
Matter camera publication was added later; see the allocation and provider
sections below.


The media session now supports both offerer and answerer roles, including the
private worker and local API. Synthetic FFmpeg/H.264 RTP reached the receiver in
both roles; 28 Python tests and six Node media tests passed. This is needed for
both `SolicitOffer` and `ProvideOffer` flows in the installed Matter WebRTC
Transport Provider definition. At this implementation stage, the Matter
command handlers, secure-fabric/peer ownership, requestor callbacks and camera
stream allocation were still missing; those were added in the later sections.


One-way audio is now wired through the ONVIF profile, worker and media session.
An `AudioEncoderConfiguration` in the discovered profile enables an Opus offer;
FFmpeg transcodes only when that audio transceiver is negotiated for sending.
The media test matrix covers both offer roles with video alone, H.264 plus Opus,
and declined audio. A hang observed with separate default transports disappeared
with explicit `max-bundle` on both test peers; the full suite then exited normally.
29 Python tests and ten Node media tests pass. Packet delivery does not yet prove
lip synchronization, audible/visual decoding, camera firmware behavior or Matter
interoperability. No microphone audio is sent back to the camera.


### Matter allocation handlers and remaining conformance

`camera-streams.mjs` validates LiveView allocation requests against the shared
encoder format in `camera-formats.mjs`, reuses compatible allocations, tracks
session references, enforces a two-session limit, and refuses deallocation of
in-use streams. `camera-av-server.mjs` connects allocation/deallocation and
priority commands to the Matter AV cluster attributes. A real, unstarted
`ServerNode`/Camera endpoint test confirmed attribute updates; all 15 Node tests
passed, including the media matrix. This does not establish full device conformance.

The video-only test endpoint did not satisfy the Camera type's Audio and
Snapshot requirements. The running bridge now composes a Camera endpoint for an
authenticated ONVIF profile that advertises video and audio, with snapshot and
WebRTC provider handlers. Its profile selector is a one-way digest, so profile
tokens and stream URIs remain private. The node also includes TLS management
clusters, a TimeSynchronization client, and a wired PowerSource component.

The root TimeSynchronization server starts unknown, accepts administrator-set
UTC, advances from a monotonic clock, and persists its last-known-good high-water
mark and NTP/time-zone/trusted-source configuration atomically with mode 0600 in
the Matter storage directory. It does not set the host clock or claim
synchronization after restart; saved sources are queried again. Required TimeSynchronization
features are implemented for UTC, time zone/DST commands, configured NTP fallback
and periodic reads from a configured trusted Matter time source. The time-zone
database reports `None`. Static checks and earlier component tests do not establish full
root conformance, commissioned-controller interoperability or actual camera
operation. No test has exercised this dynamically composed runtime endpoint
against a controller or the target hardware.
The allocation tests at that stage did not cover fabric ownership, signaling
callbacks, snapshots, microphone controls, controller commissioning or real
hardware. Later sections record the subsequent provider and snapshot work.


Snapshot allocation/deallocation and CaptureSnapshot are now implemented in the
AV behavior when a capture callback is supplied. The callback implementation
fetches the existing loopback ONVIF snapshot route, rejects redirects, bounds
input to 8 MiB, inspects JPEG dimensions before decoding (maximum 8192 per axis
and 16 megapixels), and converts to a 640×360 JPEG using a pipe-only FFmpeg input.
Output is capped at 256 KiB and conversion at ten seconds. Snapshot leases share
the allocator's encoder capacity and are released even on conversion failure.
Nineteen Node tests pass, including independent FFmpeg decoding/ffprobe dimension
checks and a failing CaptureSnapshot on a real unstarted Matter endpoint. The
test endpoint no longer reports a missing Snapshot feature. At that stage,
audio controls, provider signaling and root/composition requirements remained
outstanding; later sections describe the follow-up implementation. Real ONVIF
capture through these handlers has not been tested against hardware.


### Provider session ownership coordinator

`camera-transport.mjs` now coordinates allocated stream references and private
backend session handles. Session lookup requires both fabric index and peer node
ID; public session attributes omit backend handles. It validates supported media
selection/options, maps Matter ICE `sdpmLineIndex` to WebRTC `sdpMLineIndex`, and
releases references on backend failure, termination and shutdown during pending
negotiation. Five coordinator tests pass with a fake backend, including
cross-fabric/cross-peer rejection and a worker arriving after shutdown. At that
stage, it was not yet connected to authenticated Matter command contexts or
requestor callbacks, and it was not a commissioned-controller interoperability
test. Re-offers, automatic
stream selection, TURN/STUN configuration and metadata remain unsupported.

A targeted TCP reachability check of the screenshot camera IP `192.168.1.173`
on ports 554, 5000 and 80 timed out from this Mac. This does not prove the camera
is offline; its current IP/network/app identity remains unconfirmed. No camera
credentials or device-setting writes were used in the check.


### Provider behavior and callback sender

`camera-provider-server.mjs` now implements SolicitOffer, ProvideOffer,
ProvideAnswer, ProvideICECandidates and EndSession over the coordinator. It
requires a remote actor and a NodeSession and derives fabric/node identity from
the authenticated session. Offers/answers are sent after the incoming exchange's
`interactionComplete` event via `ServerNode.peers.forAddress` and a typed Matter
Invoke targeting WebRTC Transport Requestor. Callback status must be Success;
failure closes the media session. Transport changes synchronize CurrentSessions
and allocation reference attributes through endpoint actions.

`camera-backend.mjs` connects the coordinator to bounded loopback HTTP requests.
The API now accepts an optional boolean `audio`, allowing video-only allocations
to suppress audio and rejecting requests to enable unadvertised audio. The direct
protocol dependency is pinned to @matter/protocol 0.18.0.

The Matter coordinator polls a loopback-only worker status route every five
seconds. If the Node media worker exits after a connection timeout or runtime
failure, the coordinator now closes its Matter session and releases the stream
allocation instead of retaining a stale session until its five-minute ceiling.
Transient status API errors do not tear down an otherwise active stream.

Thirty Python tests and 27 Node tests passed. The offline endpoint no longer
reports unimplemented provider commands; it rejects unauthenticated local
signaling calls. A fake peer verified callback TLV construction and response
status handling, not delivery to a commissioned controller. When a worker exits
unexpectedly, or a provider session reaches its five-minute limit, the coordinator
now releases the local session and sends Matter `End` to the authenticated
requestor. These use the cluster's `UnknownReason` and `MediaTimeout` values
respectively. Controller-initiated `EndSession` and local shutdown do not send an
`End` echo. Fabric deletion now closes that fabric's active camera sessions and
clears a trusted time source bound to it. Remaining integration work includes
audio controls, re-offers and automatic stream selection. These are not a
completion or interoperability claim.
