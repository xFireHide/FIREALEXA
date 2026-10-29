import { TimeSynchronizationServer } from "@matter/main/behaviors/time-synchronization";
import { TimeSynchronization } from "@matter/main/clusters/time-synchronization";
import { MATTER_EPOCH_OFFSET_US, Status, StatusResponseError } from "@matter/main/types";
import { PeerAddress, Read, Val } from "@matter/protocol";
import { randomBytes, randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { createSocket } from "node:dgram";
import { isIP } from "node:net";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";

const MAX_UTC = (1n << 64n) - 2n;
const G = TimeSynchronization.Granularity;
const TS = TimeSynchronization.TimeSource;
const MATTER_EPOCH_SECONDS = 946_684_800n;

function timezoneDefaults() {
  const name = Intl.DateTimeFormat().resolvedOptions().timeZone || "Etc/UTC";
  const offset = -new Date().getTimezoneOffset() * 60;
  return { name, offset };
}

function validNtpAddress(value) {
  if (value === null) return true;
  if (typeof value !== "string" || value.length < 1 || value.length > 253 ||
      value.startsWith("[") || value.includes(":") && isIP(value) !== 6 ||
      /[\s/@?#]/.test(value)) return false;
  if (isIP(value)) return isIP(value) === 6;
  return value.split(".").every(label => label.length > 0 && label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
}

// This module keeps time as microseconds since the Matter epoch (2000-01-01),
// which is also what the UTC storage file holds. matter.js exposes epoch-us
// attributes and command fields as Unix-epoch microseconds and converts them on
// the wire, so values are translated only where they cross into matter.js.
function toMatterJsUs(value) {
  return value === null || value === undefined ? value : BigInt(value) + MATTER_EPOCH_OFFSET_US;
}

function fromMatterJsUs(value) {
  // Invalid types pass through unchanged for the caller's validation to reject;
  // values before the Matter epoch become negative and are rejected the same way.
  return typeof value === "bigint" || Number.isSafeInteger(value)
    ? BigInt(value) - MATTER_EPOCH_OFFSET_US : value;
}

function validMatterTimestamp(value) {
  return (typeof value === "bigint" && value >= 0n && value <= MAX_UTC) ||
    (Number.isSafeInteger(value) && value >= 0);
}

function validateStoredSettings(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).some(key => !["defaultNtp", "timeZone", "dstOffset", "trustedTimeSource"].includes(key))) {
    throw new Error("Invalid time settings");
  }
  const result = {};
  if ("defaultNtp" in value) {
    if (!validNtpAddress(value.defaultNtp)) throw new Error("Invalid NTP setting");
    result.defaultNtp = value.defaultNtp;
  }
  if ("timeZone" in value) {
    const zones = value.timeZone;
    if (!Array.isArray(zones) || zones.length < 1 || zones.length > 2 ||
        !/^0$/.test(String(zones[0]?.validAt)) ||
        zones.some((zone, index) => !Number.isInteger(zone?.offset) ||
          zone.offset < -64_800 || zone.offset > 64_800 ||
          !/^\d{1,20}$/.test(String(zone.validAt)) || BigInt(zone.validAt) > MAX_UTC ||
          (index > 0 && BigInt(zone.validAt) <= BigInt(zones[index - 1].validAt)) ||
          (zone.name !== undefined && (typeof zone.name !== "string" || Buffer.byteLength(zone.name) > 64)))) {
      throw new Error("Invalid time zone setting");
    }
    result.timeZone = zones.map(zone => ({ ...zone, validAt: String(zone.validAt) }));
  }
  if ("dstOffset" in value) {
    const entries = value.dstOffset;
    if (!Array.isArray(entries) || entries.length > 4 || entries.some((entry, index) =>
      !Number.isInteger(entry?.offset) || entry.offset < -2_147_483_648 || entry.offset > 2_147_483_647 ||
      !/^\d{1,20}$/.test(String(entry.validStarting)) || BigInt(entry.validStarting) > MAX_UTC ||
      (entry.validUntil !== null && (!/^\d{1,20}$/.test(String(entry.validUntil)) ||
        BigInt(entry.validUntil) <= BigInt(entry.validStarting) || BigInt(entry.validUntil) > MAX_UTC)) ||
      (index > 0 && (entries[index - 1].validUntil === null ||
        BigInt(entry.validStarting) < BigInt(entries[index - 1].validUntil))))) {
      throw new Error("Invalid daylight-saving setting");
    }
    result.dstOffset = entries.map(entry => ({ ...entry,
      validStarting: String(entry.validStarting),
      validUntil: entry.validUntil === null ? null : String(entry.validUntil),
    }));
  }
  if ("trustedTimeSource" in value) {
    const source = value.trustedTimeSource;
    if (source !== null && (!source || typeof source !== "object" ||
        !/^\d{1,20}$/.test(String(source.nodeId)) || BigInt(source.nodeId) < 1n ||
        BigInt(source.nodeId) > MAX_UTC || !Number.isInteger(source.endpoint) ||
        source.endpoint < 0 || source.endpoint > 65534 || !Number.isInteger(source.fabricIndex) ||
        source.fabricIndex < 1 || source.fabricIndex > 254)) {
      throw new Error("Invalid trusted time source setting");
    }
    result.trustedTimeSource = source === null ? null : { ...source, nodeId: String(source.nodeId) };
  }
  return result;
}

async function queryNtp(address) {
  const addresses = isIP(address) ? [{ address, family: isIP(address) }] :
    [await lookup(address, { family: 0 })];
  const target = addresses[0];
  const socket = createSocket(target.family === 6 ? "udp6" : "udp4");
  const nonce = randomBytes(8);
  try {
    const packet = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("NTP timeout")), 4_000);
      socket.once("error", error => { clearTimeout(timeout); reject(error); });
      socket.once("message", message => { clearTimeout(timeout); resolve(message); });
      const request = Buffer.alloc(48);
      request[0] = 0x23;
      nonce.copy(request, 40);
      socket.send(request, 123, target.address, error => {
        if (error) { clearTimeout(timeout); reject(error); }
      });
    });
    if (packet.length < 48 || (packet[0] & 0x7) !== 4 || packet[0] >> 6 === 3 ||
        packet[1] < 1 || packet[1] > 15 || !packet.subarray(24, 32).equals(nonce)) {
      throw new Error("Invalid NTP response");
    }
    const seconds = BigInt(packet.readUInt32BE(40)) - MATTER_EPOCH_SECONDS;
    const fraction = BigInt(packet.readUInt32BE(44)) * 1_000_000n / (1n << 32n);
    const utcTime = seconds * 1_000_000n + fraction;
    if (utcTime < 0n || utcTime > MAX_UTC) throw new Error("NTP time outside Matter range");
    return utcTime;
  } finally { socket.close(); }
}

/** Node-local UTC clock. It never changes the operating system clock and stays
 * unsynchronized after restart until an administrator supplies a valid time.
 */
export class CameraClock {
  #anchor = null;
  #monoAnchor = 0n;
  #monotonic;
  #persist;
  #settings;
  #lastKnownGood;
  #granularity = G.NoTimeGranularity;
  #timeSource = TS.None;
  #pending = false;
  constructor({ monotonic = () => process.hrtime.bigint() / 1000n,
    persist, lastKnownGood = 0n, settings = {} } = {}) {
    if (typeof persist !== "function") throw new Error("UTC clock requires a last-known-good persistence callback");
    if (typeof lastKnownGood !== "bigint" || lastKnownGood < 0n || lastKnownGood > MAX_UTC) {
      throw new Error("Invalid last-known-good UTC");
    }
    this.#monotonic = monotonic;
    this.#persist = persist;
    this.#lastKnownGood = lastKnownGood;
    this.#settings = structuredClone(settings);
  }
  get lastKnownGood() { return this.#lastKnownGood; }
  get granularity() { return this.#granularity; }
  get timeSource() { return this.#timeSource; }
  get settings() { return structuredClone(this.#settings); }
  now() {
    if (this.#anchor === null) return null;
    const elapsed = this.#monotonic() - this.#monoAnchor;
    const value = this.#anchor + (elapsed < 0n ? 0n : elapsed);
    return value <= MAX_UTC ? value : null;
  }
  async set({ utcTime, granularity, timeSource = TS.Admin }) {
    if (this.#pending) throw new StatusResponseError("UTC update in progress", Status.Busy);
    if ((typeof utcTime !== "bigint" && !Number.isSafeInteger(utcTime)) ||
        !Number.isInteger(granularity) || granularity < G.MinutesGranularity || granularity > G.MicrosecondsGranularity) {
      throw new StatusResponseError("Invalid UTC time or granularity", Status.ConstraintError);
    }
    const requested = BigInt(utcTime);
    if (requested < 0n || requested > MAX_UTC) throw new StatusResponseError("UTC time is outside the Matter range", Status.ConstraintError);
    this.#pending = true;
    const monoAnchor = this.#monotonic();
    const value = [requested, this.#lastKnownGood, this.now() ?? 0n].reduce((a, b) => a > b ? a : b);
    if (!Object.values(TS).includes(timeSource)) {
      this.#pending = false;
      throw new StatusResponseError("Invalid UTC time source", Status.ConstraintError);
    }
    const highWater = value;
    try {
      await this.#persist(highWater, this.#settings);
      this.#anchor = value;
      this.#monoAnchor = monoAnchor;
      this.#lastKnownGood = highWater;
      this.#timeSource = timeSource;
      // Account for drift rather than claiming the sender's precision.
      this.#granularity = Math.max(G.MinutesGranularity, granularity - 1);
    } catch {
      throw new StatusResponseError("UTC persistence failed", Status.Failure);
    } finally { this.#pending = false; }
  }

  async setSettings(settings) {
    if (this.#pending) throw new StatusResponseError("UTC storage update in progress", Status.Busy);
    this.#pending = true;
    const next = structuredClone(settings);
    try {
      await this.#persist(this.#lastKnownGood, next);
      this.#settings = next;
    } catch {
      throw new StatusResponseError("Time settings persistence failed", Status.Failure);
    } finally { this.#pending = false; }
  }
}

export async function loadCameraClock(path, { monotonic } = {}) {
  let lastKnownGood = 0n;
  let settings = {};
  try {
    const fileInfo = await lstat(path);
    if (!fileInfo.isFile() || fileInfo.size > 16 * 1024) throw new Error("UTC storage must be a small regular file");
    const data = JSON.parse(await readFile(path, "utf8"));
    if (data.version !== 1 || typeof data.lastKnownGood !== "string" || !/^\d{1,20}$/.test(data.lastKnownGood)) {
      throw new Error("Invalid UTC storage");
    }
    lastKnownGood = BigInt(data.lastKnownGood);
    if (lastKnownGood > MAX_UTC) throw new Error("Invalid UTC high-water mark");
    if (data.settings !== undefined) settings = validateStoredSettings(data.settings);
  } catch (error) {
    if (error.code !== "ENOENT") throw new Error("Unable to load UTC storage");
  }
  return new CameraClock({ monotonic, lastKnownGood, settings, persist: async (value, nextSettings) => {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const temporary = `${path}.${randomUUID()}.tmp`;
    try {
      const file = await open(temporary, "wx", 0o600);
      try {
        await file.writeFile(JSON.stringify({ version: 1, lastKnownGood: String(value),
          settings: nextSettings }));
        await file.sync();
      } finally { await file.close(); }
      await rename(temporary, path);
      const directory = await open(dirname(path), "r");
      try { await directory.sync(); } finally { await directory.close(); }
    } finally { await unlink(temporary).catch(() => {}); }
  } });
}

export function createCameraTimeServer(clock, getNode = () => undefined) {
  const Base = TimeSynchronizationServer.with("TimeZone", "NtpClient", "TimeSyncClient");
  const initialZone = timezoneDefaults();
  const stored = validateStoredSettings(clock.settings);
  let zones = stored.timeZone?.map(zone => ({ ...zone, validAt: BigInt(zone.validAt) })) ??
    [{ offset: initialZone.offset, validAt: 0n, name: initialZone.name }];
  let dstOffsets = stored.dstOffset?.map(entry => ({ ...entry,
    validStarting: BigInt(entry.validStarting),
    validUntil: entry.validUntil === null ? null : BigInt(entry.validUntil),
  })) ?? [{ offset: 0, validStarting: 0n, validUntil: null }];
  let defaultNtp = stored.defaultNtp ?? null;
  let trustedTimeSource = stored.trustedTimeSource ? {
    ...stored.trustedTimeSource, nodeId: BigInt(stored.trustedTimeSource.nodeId),
  } : null;
  let trustedSyncTimer;
  let trustedSyncActive = false;
  let ntpSyncTimer;
  let ntpSyncActive = false;
  let lastTimeFailure = 0;
  let lastMissingTrustedSource = 0;

  async function persistSettings(overrides = {}) {
    const next = {
      defaultNtp,
      timeZone: zones,
      dstOffset: dstOffsets,
      trustedTimeSource,
      ...overrides,
    };
    await clock.setSettings({
      defaultNtp: next.defaultNtp,
      timeZone: next.timeZone.map(zone => ({ ...zone, validAt: String(zone.validAt) })),
      dstOffset: next.dstOffset.map(entry => ({ ...entry,
        validStarting: String(entry.validStarting),
        validUntil: entry.validUntil === null || entry.validUntil === undefined
          ? null : String(entry.validUntil),
      })),
      trustedTimeSource: next.trustedTimeSource === null ? null : {
        ...next.trustedTimeSource, nodeId: String(next.trustedTimeSource.nodeId),
      },
    });
  }

  function emitRateLimited(name, lastSent, updateLastSent) {
    if (Date.now() - lastSent() < 3_600_000) return;
    updateLastSent(Date.now());
    return name;
  }

  async function syncTrustedTime(events, context) {
    if (trustedSyncActive || !trustedTimeSource) return;
    trustedSyncActive = true;
    let synchronized = false;
    try {
      const node = getNode();
      if (!node) return;
      const peer = await node.peers.forAddress(PeerAddress({
        fabricIndex: trustedTimeSource.fabricIndex, nodeId: trustedTimeSource.nodeId,
      }));
      const interaction = peer.interaction;
      if (!interaction) return;
      const request = Read({ attributes: [
        { endpointId: trustedTimeSource.endpoint, clusterId: TimeSynchronization.id,
          attributeId: TimeSynchronization.attributes.utcTime.id },
        { endpointId: trustedTimeSource.endpoint, clusterId: TimeSynchronization.id,
          attributeId: TimeSynchronization.attributes.granularity.id },
      ] });
      let utcTime;
      let granularity;
      for await (const chunk of interaction.read(request)) {
        for (const report of chunk) {
          if (report.kind !== "attr-value") continue;
          if (report.path.attributeId === TimeSynchronization.attributes.utcTime.id) utcTime = report.value;
          if (report.path.attributeId === TimeSynchronization.attributes.granularity.id) granularity = report.value;
        }
      }
      if ((typeof utcTime === "bigint" || Number.isSafeInteger(utcTime)) &&
          Number.isInteger(granularity) && granularity >= G.MinutesGranularity &&
          granularity <= G.MicrosecondsGranularity) {
        await clock.set({ utcTime: fromMatterJsUs(utcTime), granularity,
          timeSource: TS.NodeTimeCluster });
        synchronized = true;
      }
    } catch { /* The trusted fabric peer may be offline; retry on the next interval. */ }
    finally {
      if (!synchronized) {
        const event = emitRateLimited("missingTrustedTimeSource", () => lastMissingTrustedSource,
          value => { lastMissingTrustedSource = value; });
        if (event) events?.missingTrustedTimeSource?.emit(undefined, context);
        if (defaultNtp !== null) void syncNtpTime(defaultNtp, events, context, true);
      }
      trustedSyncActive = false;
    }
  }

  async function syncNtpTime(address, events, context, fallback = false) {
    if (ntpSyncActive || !address || (trustedTimeSource && !fallback)) return;
    ntpSyncActive = true;
    try {
      const utcTime = await queryNtp(address);
      await clock.set({ utcTime, granularity: G.MillisecondsGranularity,
        timeSource: TS.NonMatterNtp });
    } catch {
      const event = emitRateLimited("timeFailure", () => lastTimeFailure,
        value => { lastTimeFailure = value; });
      if (event) events?.timeFailure?.emit(undefined, context);
    } finally { ntpSyncActive = false; }
  }

  function scheduleNtp(events, context) {
    clearInterval(ntpSyncTimer);
    if (!defaultNtp) return;
    void syncNtpTime(defaultNtp, events, context);
    ntpSyncTimer = setInterval(() => { void syncNtpTime(defaultNtp, events, context); },
      6 * 60 * 60 * 1000);
    ntpSyncTimer.unref?.();
  }

  function scheduleTrustedSource(events, context) {
    clearInterval(trustedSyncTimer);
    if (!trustedTimeSource) return;
    const initialSync = setTimeout(() => { void syncTrustedTime(events, context); }, 1_000);
    initialSync.unref?.();
    trustedSyncTimer = setInterval(() => { void syncTrustedTime(events, context); }, 60_000);
    trustedSyncTimer.unref?.();
  }

  class CameraTimeServer extends Base {
    initialize() {
      scheduleNtp(this.events, this.context);
      scheduleTrustedSource(this.events, this.context);
    }
    async setUtcTime(request) {
      await clock.set({ ...request, utcTime: fromMatterJsUs(request?.utcTime) });
    }
    async setDefaultNtp({ defaultNtp: address }) {
      if (!validNtpAddress(address)) throw new StatusResponseError("Invalid NTP address", Status.ConstraintError);
      await persistSettings({ defaultNtp: address });
      defaultNtp = address;
      scheduleNtp(this.events, this.context);
    }
    async setTrustedTimeSource({ trustedTimeSource: source }) {
      if (source === null) {
        await persistSettings({ trustedTimeSource: null });
        trustedTimeSource = null;
        scheduleTrustedSource(this.events, this.context);
        this.events.missingTrustedTimeSource?.emit(undefined, this.context);
        if (defaultNtp !== null) void syncNtpTime(defaultNtp, this.events, this.context);
        return;
      }
      const session = this.context?.session;
      if (!session?.peerAddress || typeof source?.nodeId !== "bigint" ||
          !Number.isInteger(source.endpoint) || source.endpoint < 0 || source.endpoint > 65534) {
        throw new StatusResponseError("Invalid trusted time source", Status.ConstraintError);
      }
      if (source.nodeId <= 0n) throw new StatusResponseError("Invalid trusted time source", Status.ConstraintError);
      const next = { ...source, fabricIndex: session.peerAddress.fabricIndex };
      await persistSettings({ trustedTimeSource: next });
      trustedTimeSource = next;
      scheduleTrustedSource(this.events, this.context);
    }
    async removeFabric(fabricIndex) {
      if (trustedTimeSource?.fabricIndex !== fabricIndex) return;
      await persistSettings({ trustedTimeSource: null });
      trustedTimeSource = null;
      scheduleTrustedSource(this.events, this.context);
    }
    async setTimeZone({ timeZone: requested }) {
      const timeZone = Array.isArray(requested)
        ? requested.map(zone => ({ ...zone, validAt: fromMatterJsUs(zone?.validAt) }))
        : requested;
      if (!Array.isArray(timeZone) || timeZone.length < 1 || timeZone.length > 2 ||
          !validMatterTimestamp(timeZone[0]?.validAt) || BigInt(timeZone[0].validAt) !== 0n ||
          timeZone.some((zone, index) => !Number.isInteger(zone?.offset) ||
            zone.offset < -64_800 || zone.offset > 64_800 ||
            !validMatterTimestamp(zone?.validAt) ||
            (index > 0 && BigInt(zone.validAt) <= BigInt(timeZone[index - 1].validAt)) ||
            (zone.name !== undefined && (typeof zone.name !== "string" ||
              Buffer.byteLength(zone.name) > 64)))) {
        throw new StatusResponseError("Invalid time zone table", Status.ConstraintError);
      }
      const nextZones = structuredClone(timeZone);
      await persistSettings({ timeZone: nextZones, dstOffset: [] });
      zones = nextZones;
      dstOffsets = [];
      const now = clock.now() ?? 0n;
      const activeZone = [...zones].reverse().find(zone => BigInt(zone.validAt) <= now) ?? zones[0];
      this.events.timeZoneStatus?.emit({ offset: activeZone.offset,
        ...(activeZone.name === undefined ? {} : { name: activeZone.name }) }, this.context);
      this.events.dstTableEmpty?.emit(undefined, this.context);
      return { dstOffsetRequired: true };
    }
    async setDstOffset({ dstOffset: requested }) {
      const dstOffset = Array.isArray(requested)
        ? requested.map(entry => ({ ...entry,
          validStarting: fromMatterJsUs(entry?.validStarting),
          validUntil: entry?.validUntil === null || entry?.validUntil === undefined
            ? entry?.validUntil : fromMatterJsUs(entry.validUntil),
        }))
        : requested;
      if (!Array.isArray(dstOffset) || dstOffset.length > 4 ||
          dstOffset.some((entry, index) => !Number.isInteger(entry?.offset) ||
            entry.offset < -2_147_483_648 || entry.offset > 2_147_483_647 ||
            !validMatterTimestamp(entry.validStarting) ||
            (entry.validUntil !== null && entry.validUntil !== undefined &&
              (!validMatterTimestamp(entry.validUntil) || BigInt(entry.validUntil) <= BigInt(entry.validStarting))) ||
            (index > 0 && (dstOffset[index - 1].validUntil === null ||
              dstOffset[index - 1].validUntil === undefined ||
              BigInt(entry.validStarting) < BigInt(dstOffset[index - 1].validUntil))))) {
        throw new StatusResponseError("Invalid daylight-saving table", Status.ConstraintError);
      }
      const nextOffsets = structuredClone(dstOffset.map(entry => ({ ...entry,
        validUntil: entry.validUntil ?? null,
      })));
      const wasActive = dstOffsets.some(entry => entry.offset !== 0 &&
        BigInt(entry.validStarting) <= (clock.now() ?? -1n) &&
        (entry.validUntil === null || entry.validUntil === undefined ||
          (clock.now() ?? -1n) < BigInt(entry.validUntil)));
      await persistSettings({ dstOffset: nextOffsets });
      dstOffsets = nextOffsets;
      const isActive = dstOffsets.some(entry => entry.offset !== 0 &&
        BigInt(entry.validStarting) <= (clock.now() ?? -1n) &&
        (entry.validUntil === null || entry.validUntil === undefined ||
          (clock.now() ?? -1n) < BigInt(entry.validUntil)));
      if (wasActive !== isActive) this.events.dstStatus?.emit({ dstOffsetActive: isActive }, this.context);
      if (!dstOffsets.length) this.events.dstTableEmpty?.emit(undefined, this.context);
    }
    static State = class extends Base.State {
      [Val.properties]() {
        return {
          get utcTime() { return toMatterJsUs(clock.now()); },
          get granularity() { return clock.now() === null ? G.NoTimeGranularity : clock.granularity; },
          get timeSource() { return clock.now() === null ? TS.None : clock.timeSource; },
          get trustedTimeSource() { return trustedTimeSource; },
          get defaultNtp() { return defaultNtp; },
          get supportsDnsResolve() { return true; },
          get timeZone() {
            return zones.map(zone => ({ ...zone, validAt: toMatterJsUs(zone.validAt) }));
          },
          get dstOffset() {
            return dstOffsets.map(entry => ({ ...entry,
              validStarting: toMatterJsUs(entry.validStarting),
              validUntil: toMatterJsUs(entry.validUntil ?? null),
            }));
          },
          get localTime() {
            const now = clock.now();
            if (now === null) return null;
            const zone = [...zones].reverse().find(entry => BigInt(entry.validAt) <= now) ?? zones[0];
            const dst = [...dstOffsets].reverse().find(entry => BigInt(entry.validStarting) <= now &&
              (entry.validUntil === null || entry.validUntil === undefined || now < BigInt(entry.validUntil)));
            if (!dst) return null;
            return toMatterJsUs(now + BigInt(zone.offset + dst.offset) * 1_000_000n);
          },
          get timeZoneDatabase() { return TimeSynchronization.TimeZoneDatabase.None; },
          get timeZoneListMaxSize() { return 2; },
          get dstOffsetListMaxSize() { return 4; },
        };
      }
    };
  }
  return CameraTimeServer;
}
