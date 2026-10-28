import { createHash } from "node:crypto";
import { Endpoint, ServerNode, VendorId } from "@matter/main";
import { QrCode } from "@matter/main/types";
import { BridgedDeviceBasicInformationServer } from "@matter/main/behaviors/bridged-device-basic-information";
import { OnOffLightDevice } from "@matter/main/devices/on-off-light";
import { OnOffPlugInUnitDevice } from "@matter/main/devices/on-off-plug-in-unit";
import { DimmableLightDevice } from "@matter/main/devices/dimmable-light";
import { ExtendedColorLightDevice } from "@matter/main/devices/extended-color-light";
import { TemperatureSensorDevice } from "@matter/main/devices/temperature-sensor";
import { HumiditySensorDevice } from "@matter/main/devices/humidity-sensor";
import { ContactSensorDevice } from "@matter/main/devices/contact-sensor";
import { OccupancySensorDevice } from "@matter/main/devices/occupancy-sensor";
import { WindowCoveringDevice } from "@matter/main/devices/window-covering";
import { OccupancySensingServer } from "@matter/main/behaviors/occupancy-sensing";
import { WindowCoveringServer } from "@matter/main/behaviors/window-covering";
import { OnOffServer } from "@matter/main/behaviors/on-off";
import { LevelControlServer } from "@matter/main/behaviors/level-control";
import { ColorControlServer } from "@matter/main/behaviors/color-control";
import { AggregatorEndpoint } from "@matter/main/endpoints/aggregator";

const apiUrl = process.env.FIREALEXA_API_URL ?? "http://127.0.0.1:8765";
const nodeId = process.env.FIREALEXA_MATTER_NODE_ID ?? "firealexa-bridge";
const port = Number(process.env.FIREALEXA_MATTER_PORT ?? 5540);
const passcode = Number(process.env.FIREALEXA_MATTER_PASSCODE);
const discriminator = Number(process.env.FIREALEXA_MATTER_DISCRIMINATOR);
const vendorId = Number(process.env.FIREALEXA_MATTER_VENDOR_ID ?? 0xfff1);
const productId = Number(process.env.FIREALEXA_MATTER_PRODUCT_ID ?? 0x8000);
const validPasscode = Number.isInteger(passcode) && passcode >= 1 && passcode <= 99_999_998 &&
  ![20_202_021, 12_345_678, 87_654_321].includes(passcode) &&
  new Set(String(passcode).padStart(8, "0")).size > 1;
if (!validPasscode) throw new Error("A valid Matter setup passcode is required");
if (!Number.isInteger(discriminator) || discriminator < 0 || discriminator > 4095) {
  throw new Error("Matter discriminator must be an integer from 0 to 4095");
}
if (!/^[A-Za-z0-9_-]{1,32}$/.test(nodeId)) {
  throw new Error("Matter node ID must use 1-32 ASCII letters, digits, '_' or '-'");
}
for (const [name, value] of [["port", port], ["vendor ID", vendorId], ["product ID", productId]]) {
  if (!Number.isInteger(value) || value < (name === "port" ? 1 : 0) || value > 65535) {
    throw new Error(`Matter ${name} must be an integer in its supported range`);
  }
}

const server = await ServerNode.create({
  id: nodeId,
  network: { port },
  commissioning: { passcode, discriminator },
  productDescription: {
    name: "FIREALEXA Local Bridge",
    deviceType: AggregatorEndpoint.deviceType,
  },
  basicInformation: {
    vendorName: "FIREALEXA",
    vendorId: VendorId(vendorId),
    nodeLabel: "FIREALEXA Bridge",
    productName: "FIREALEXA Local Bridge",
    productLabel: "FIREALEXA Local Bridge",
    productId,
    serialNumber: nodeId,
    uniqueId: nodeId,
  },
});
const aggregator = new Endpoint(AggregatorEndpoint, { id: "aggregator" });
await server.add(aggregator);

const endpoints = new Map();
const PENDING_STATE_TTL_MS = 30_000;
const identity = (device) => `${device.brand}:${device.device_id}`;
const endpointId = (key) => `dev-${createHash("sha256").update(key).digest("hex").slice(0, 20)}`;
// Matter temperatures use signed hundredths of a degree; humidity uses
// Percent100ths with a 0..10000 range.
const MIN_CENTI_CELSIUS = -27_315;
const MAX_CENTI_CELSIUS = 32_767;
const MAX_CENTI_PERCENT = 10_000;
const matterText = (value, maxBytes = 32) => {
  let result = "";
  let size = 0;
  for (const character of String(value)) {
    const characterSize = Buffer.byteLength(character, "utf8");
    if (size + characterSize > maxBytes) break;
    result += character;
    size += characterSize;
  }
  return result || "Device";
};
const toMatterLevel = (brightness) => {
  const percent = typeof brightness === "number" && Number.isFinite(brightness)
    ? Math.max(0, Math.min(100, brightness)) : 1;
  return Math.max(1, Math.min(254, Math.round(percent * 254 / 100)));
};
const toBrightness = (level) => Math.max(1, Math.min(100, Math.round(level * 100 / 254)));
const toMatterHue = (hue) => Math.max(0, Math.min(254, Math.round(hue * 254 / 360)));
const toMatterSaturation = (saturation) => Math.max(0, Math.min(254,
  Math.round(saturation * 254 / 100)));
const toHue = (hue) => Math.max(0, Math.min(360, hue * 360 / 254));
const toSaturation = (saturation) => Math.max(0, Math.min(100, saturation * 100 / 254));
const toCentiCelsius = (value) => typeof value === "number" && Number.isFinite(value) &&
  value >= MIN_CENTI_CELSIUS / 100 && value <= MAX_CENTI_CELSIUS / 100
    ? Math.round(value * 100) : null;
const toCentiPercent = (value) => typeof value === "number" && Number.isFinite(value) &&
  value >= 0 && value <= MAX_CENTI_PERCENT / 100 ? Math.round(value * 100) : null;
const hasTemperatureSample = (device) =>
  toCentiCelsius(device.state?.temperature) !== null;
const hasHumiditySample = (device) =>
  toCentiPercent(device.state?.humidity) !== null;
const channelSwitches = (device) => device.brand === "ewelink" &&
  Array.isArray(device.state?.raw?.switches) ? device.state.raw.switches : undefined;
const isDualR3 = (device) => device.brand === "ewelink" &&
  (device.uiid === 126 || ["UIID_126", "DUALR3"].includes(device.model));
const dualR3RelayMode = (device) => !isDualR3(device) ||
  device.state?.raw?.params?.workMode === 1;
const channelNumbers = (device) => [...new Set((channelSwitches(device) ?? [])
  .map((entry) => entry?.outlet)
  .filter((outlet) => Number.isInteger(outlet) && outlet >= 0 && outlet <= 31))];
const hasChannelEndpoints = (baseKey) => [...endpoints.keys()]
  .some((key) => key.startsWith(`${baseKey}:channel:`));
const onState = (device, channel) => {
  if (channel === undefined) {
    return typeof device.state?.on === "boolean" ? device.state.on : undefined;
  }
  const value = channelSwitches(device)?.find((entry) => entry?.outlet === channel)?.switch;
  return value === "on" ? true : value === "off" ? false : undefined;
};
const isDimmableType = (type) => ["DIMMABLE_LIGHT", "COLOR_LIGHT"].includes(type);
const deviceClass = (type, uiid) => {
  if (type === "ON_OFF_PLUG" || type === "THERMOSTAT") return OnOffPlugInUnitDevice;
  if (type === "ON_OFF_LIGHT") return OnOffLightDevice;
  if (type === "COLOR_LIGHT" && [22, 59].includes(uiid)) return ExtendedColorLightDevice;
  if (["DIMMABLE_LIGHT", "COLOR_LIGHT"].includes(type)) return DimmableLightDevice;
  return undefined;
};
const MotionSensorDevice = OccupancySensorDevice.with(
  OccupancySensingServer.with("PassiveInfrared", "OccupancyEvent"),
);
const CameraMotionSensorDevice = OccupancySensorDevice.with(
  OccupancySensingServer.with("OccupancyEvent"),
);
const controlledOnOffServer = (writeState, BaseServer) => class ControlledOnOffServer
  extends BaseServer {
  async on() {
    await writeState({ on: true });
    return super.on();
  }

  async off() {
    await writeState({ on: false });
    return super.off();
  }
};
const controlledWindowCoveringServer = (writeState) =>
  class ControlledWindowCoveringServer extends WindowCoveringServer.with("Lift") {
    async upOrOpen() {
      await writeState({ cover: { direction: "open" } });
      return super.upOrOpen();
    }

    async downOrClose() {
      await writeState({ cover: { direction: "close" } });
      return super.downOrClose();
    }

    async stopMotion() {
      await writeState({ cover: { direction: "stop" } });
      return super.stopMotion();
    }
  };
const controlledLevelControlServer = (writeState) => class ControlledLevelControlServer
  extends LevelControlServer.with("Lighting", "OnOff") {
  async transition(targetLevel, _changePerS, withOnOff = false, options = {}) {
    if (typeof targetLevel !== "number") return super.transition(targetLevel, 0, withOnOff, options);
    const level = targetLevel === Infinity ? this.maxLevel : targetLevel === -Infinity
      ? this.minLevel : Math.max(this.minLevel, Math.min(this.maxLevel, targetLevel));
    const brightness = toBrightness(level);
    const command = withOnOff && level <= this.minLevel
      ? { on: false }
      : withOnOff ? { on: true, brightness } : { brightness };
    await writeState(command);
    return super.transition(level, 0, withOnOff, options);
  }
};
const controlledColorControlServer = (writeState, uiid) => {
  const features = uiid === 22
    ? ["HueSaturation", "ColorTemperature"] : ["HueSaturation"];
  return class ControlledColorControlServer extends ColorControlServer.with(...features) {
    #movementTimer;
    #movementWriteActive = false;
    #movementKind;

    #stopMovementTimer() {
      clearInterval(this.#movementTimer);
      this.#movementTimer = undefined;
      this.#movementKind = undefined;
    }

    #startMovementSync(kind) {
      this.#stopMovementTimer();
      this.#movementKind = kind;
      this.#movementTimer = setInterval(async () => {
        if (this.#movementWriteActive) return;
        this.#movementWriteActive = true;
        try {
          await this.#writeCurrentColor(kind);
        } catch (error) {
          console.error("Matter color movement could not reach the eWeLink light:", error);
        } finally {
          this.#movementWriteActive = false;
        }
      }, 300);
      this.#movementTimer.unref?.();
    }

    async #writeCurrentColor(kind) {
      if (kind === "temperature") {
        await writeState({ color_temp: Math.max(154, Math.min(500,
          Math.round(this.state.colorTemperatureMireds))) });
      } else {
        await writeState({
          hue: toHue(this.state.currentHue),
          saturation: toSaturation(this.state.currentSaturation),
        });
      }
    }

    async #flushMovement(kind) {
      this.#stopMovementTimer();
      while (this.#movementWriteActive) {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      await this.#writeCurrentColor(kind);
    }

    async moveToHueLogic(targetHue, direction, transitionTime, isEnhancedHue = false) {
      this.#stopMovementTimer();
      await writeState({
        hue: targetHue * 360 / (isEnhancedHue ? 65_535 : 254),
        saturation: toSaturation(this.state.currentSaturation),
      });
      return super.moveToHueLogic(targetHue, direction, transitionTime, isEnhancedHue);
    }

    async moveToSaturationLogic(targetSaturation, transitionTime) {
      this.#stopMovementTimer();
      await writeState({
        hue: toHue(this.state.currentHue),
        saturation: toSaturation(targetSaturation),
      });
      return super.moveToSaturationLogic(targetSaturation, transitionTime);
    }

    async moveToHueAndSaturationLogic(targetHue, targetSaturation, transitionTime) {
      this.#stopMovementTimer();
      await writeState({
        hue: toHue(targetHue),
        saturation: toSaturation(targetSaturation),
      });
      await super.moveToHueLogic(targetHue, 0, transitionTime, false);
      return super.moveToSaturationLogic(targetSaturation, transitionTime);
    }

    async moveToColorTemperatureLogic(targetMireds, transitionTime) {
      if (uiid !== 22) throw new Error("Color temperature is unavailable on this eWeLink light");
      this.#stopMovementTimer();
      await writeState({ color_temp: Math.max(154, Math.min(500, Math.round(targetMireds))) });
      return super.moveToColorTemperatureLogic(targetMireds, transitionTime);
    }

    async moveHueLogic(moveMode, rate, isEnhancedHue = false) {
      this.#startMovementSync("hue-saturation");
      return super.moveHueLogic(moveMode, rate, isEnhancedHue);
    }

    async moveSaturationLogic(moveMode, rate) {
      this.#startMovementSync("hue-saturation");
      return super.moveSaturationLogic(moveMode, rate);
    }

    async stopHueAndSaturationMovement() {
      if (this.#movementKind === "hue-saturation") {
        await this.#flushMovement("hue-saturation");
      } else {
        this.#stopMovementTimer();
      }
      return super.stopHueAndSaturationMovement();
    }

    async stepHueLogic(stepMode, stepSize, transitionTime, isEnhancedHue = false) {
      this.#stopMovementTimer();
      const maximum = isEnhancedHue ? 65_535 : 254;
      const key = isEnhancedHue ? "enhancedCurrentHue" : "currentHue";
      const direction = stepMode === 1 ? 1 : -1;
      const targetHue = (this.state[key] + direction * stepSize + maximum + 1) % (maximum + 1);
      await writeState({
        hue: targetHue * 360 / maximum,
        saturation: toSaturation(this.state.currentSaturation),
      });
      return super.stepHueLogic(stepMode, stepSize, transitionTime, isEnhancedHue);
    }

    async stepSaturationLogic(stepMode, stepSize, transitionTime) {
      this.#stopMovementTimer();
      const direction = stepMode === 1 ? 1 : -1;
      const targetSaturation = Math.max(0, Math.min(254,
        this.state.currentSaturation + direction * stepSize));
      await writeState({
        hue: toHue(this.state.currentHue),
        saturation: toSaturation(targetSaturation),
      });
      return super.stepSaturationLogic(stepMode, stepSize, transitionTime);
    }

    async moveColorTemperatureLogic(...args) {
      if (uiid !== 22) throw new Error("Color temperature is unavailable on this eWeLink light");
      this.#startMovementSync("temperature");
      return super.moveColorTemperatureLogic(...args);
    }

    async stepColorTemperatureLogic(
      stepMode, stepSize, transitionTime, minimumMireds, maximumMireds,
    ) {
      if (uiid !== 22) throw new Error("Color temperature is unavailable on this eWeLink light");
      this.#stopMovementTimer();
      const direction = stepMode === 1 ? 1 : -1;
      const minimum = Math.max(154, minimumMireds ?? 154);
      const maximum = Math.min(500, maximumMireds ?? 500);
      const targetMireds = Math.max(minimum, Math.min(maximum,
        this.state.colorTemperatureMireds + direction * stepSize));
      await writeState({ color_temp: targetMireds });
      return super.stepColorTemperatureLogic(
        stepMode, stepSize, transitionTime, minimumMireds, maximumMireds,
      );
    }

    async stopAllColorMovement() {
      if (this.#movementKind) {
        await this.#flushMovement(this.#movementKind);
      } else {
        this.#stopMovementTimer();
      }
      return super.stopAllColorMovement();
    }

    async [Symbol.asyncDispose]() {
      this.#stopMovementTimer();
      return super[Symbol.asyncDispose]();
    }
  };
};

async function request(path, options = {}) {
  const { timeoutMs = 5000, ...fetchOptions } = options;
  let response;
  try {
    response = await fetch(`${apiUrl}${path}`, {
      ...fetchOptions,
      headers: { "content-type": "application/json", ...fetchOptions.headers },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (cause) {
    throw new ApiConnectionError(cause);
  }
  if (!response.ok) throw new Error(`Bridge API ${response.status}: ${await response.text()}`);
  return response.status === 204 ? undefined : response.json();
}

class ApiConnectionError extends Error {
  constructor(cause) {
    super(`Could not connect to bridge API at ${apiUrl}`, { cause });
    this.name = "ApiConnectionError";
  }
}

async function markEndpointsUnreachable() {
  for (const [key, record] of endpoints) {
    try {
      await record.endpoint.set({ bridgedDeviceBasicInformation: { reachable: false } });
    } catch (error) {
      console.error(`Could not mark Matter endpoint ${key} unreachable:`, error);
    }
  }
}

async function addDevice(device) {
  const baseKey = identity(device);
  const name = device.name || device.model || device.device_id;
  const available = [];
  if (device.type === "WINDOW_COVERING" && device.brand === "ewelink" && device.uiid === 126) {
    available.push({ key: baseKey, kind: WindowCoveringDevice, capability: "cover" });
  }
  const switchKind = deviceClass(device.type, device.uiid);
  const channels = channelNumbers(device);
  if (switchKind && dualR3RelayMode(device)) {
    if (channels.length) {
      for (const channel of channels) {
        // OnOff has a mandatory boolean initial value. Do not invent "off"
        // when the adapter has only discovered the channel but has not read
        // its state yet; synchronize() will retry endpoint creation later.
        if (typeof onState(device, channel) !== "boolean") continue;
        available.push({
          key: `${baseKey}:channel:${channel}`,
          kind: switchKind,
          capability: "onOff",
          channel,
        });
      }
    } else if (!isDualR3(device) && channelSwitches(device) === undefined &&
        !hasChannelEndpoints(baseKey) && typeof onState(device) === "boolean") {
      available.push({
        key: baseKey,
        kind: switchKind,
        capability: "onOff",
        dimmable: isDimmableType(device.type),
        color: device.type === "COLOR_LIGHT" && [22, 59].includes(device.uiid)
          ? device.uiid : undefined,
      });
    }
  }
  // BooleanState has no useful default for an unknown contact reading: false
  // would assert "closed" before the adapter has observed the device.
  if (device.type === "CONTACT_SENSOR" && typeof device.state?.contact_open === "boolean") {
    available.push({ key: baseKey, kind: ContactSensorDevice, capability: "contact" });
  }
  // Likewise, do not publish an unoccupied reading until we have an actual
  // occupancy sample. synchronize() retries endpoint creation every cycle.
  if (device.type === "MOTION_SENSOR" && typeof device.state?.motion_detected === "boolean") {
    available.push({ key: baseKey, kind: MotionSensorDevice, capability: "motion" });
  }
  if (device.type === "CAMERA" && typeof device.state?.motion_detected === "boolean") {
    available.push({ key: `${baseKey}:motion`, kind: CameraMotionSensorDevice,
      capability: "cameraMotion" });
  }
  if (device.type === "THERMOSTAT") {
    if (hasTemperatureSample(device)) {
      available.push({ key: `${baseKey}:temperature`, kind: TemperatureSensorDevice,
        capability: "temperature" });
    }
    if (hasHumiditySample(device)) {
      available.push({ key: `${baseKey}:humidity`, kind: HumiditySensorDevice,
        capability: "humidity" });
    }
  } else if (device.type === "TEMPERATURE_SENSOR" || device.type === "ENVIRONMENT_SENSOR") {
    if (hasTemperatureSample(device)) {
      available.push({ key: `${baseKey}:temperature`, kind: TemperatureSensorDevice,
        capability: "temperature" });
    }
    if (hasHumiditySample(device)) {
      available.push({ key: `${baseKey}:humidity`, kind: HumiditySensorDevice,
        capability: "humidity" });
    }
  } else if (device.type === "IR_REMOTE") {
    if (hasTemperatureSample(device)) {
      available.push({ key: `${baseKey}:temperature`, kind: TemperatureSensorDevice,
        capability: "temperature" });
    }
    if (hasHumiditySample(device)) {
      available.push({ key: `${baseKey}:humidity`, kind: HumiditySensorDevice,
        capability: "humidity" });
    }
  } else if (device.type === "HUMIDITY_SENSOR" && hasHumiditySample(device)) {
    available.push({ key: baseKey, kind: HumiditySensorDevice, capability: "humidity" });
  }

  for (const item of available) {
    if (endpoints.has(item.key)) continue;
    try {
      let record;
      const writeState = async (state) => {
        const previous = record.pendingCommand;
        const pending = {
          ...(previous && Date.now() - previous.sentAt <= PENDING_STATE_TTL_MS ? previous : {}),
          ...state,
          sentAt: Date.now(),
        };
        if ("color_temp" in state) {
          delete pending.hue;
          delete pending.saturation;
        } else if ("hue" in state || "saturation" in state) {
          delete pending.color_temp;
        }
        record.pendingCommand = pending;
        try {
          await request(`/api/devices/${encodeURIComponent(device.brand)}/${encodeURIComponent(device.device_id)}/state`, {
            method: "PUT",
            // Allows Broadlink session renewal/retry plus the API's state refresh.
            timeoutMs: 20_000,
            body: JSON.stringify({ ...state,
              ...(item.channel === undefined ? {} : { channel: item.channel }) }),
          });
        } catch (error) {
          if (record.pendingCommand === pending) record.pendingCommand = previous;
          throw error;
        }
      };
      const behaviors = [BridgedDeviceBasicInformationServer];
      if (item.capability === "onOff") {
        const hasLightingFeature = ["ON_OFF_LIGHT", "DIMMABLE_LIGHT", "COLOR_LIGHT"]
          .includes(device.type);
        const onOffBase = hasLightingFeature ? OnOffServer.with("Lighting") : OnOffServer;
        behaviors.push(controlledOnOffServer(writeState, onOffBase));
      }
      if (item.capability === "cover") {
        behaviors.push(controlledWindowCoveringServer(writeState));
      }
      if (item.dimmable) behaviors.push(controlledLevelControlServer(writeState));
      if (item.color) behaviors.push(controlledColorControlServer(writeState, item.color));
      const initial = {
        bridgedDeviceBasicInformation: {
          nodeLabel: matterText(`${name}${item.channel !== undefined ? ` Channel ${item.channel + 1}` :
            item.capability === "temperature" ? " Temperature" :
            item.capability === "humidity" ? " Humidity" : ""}`),
          productName: matterText(device.model || name),
          productLabel: matterText(name, 64),
          serialNumber: createHash("sha256").update(item.key).digest("hex").slice(0, 32),
          reachable: device.online === true,
        },
      };
      if (item.capability === "onOff") initial.onOff = {
        onOff: onState(device, item.channel) === true,
      };
      if (item.capability === "cover") {
        const movement = { opening: 1, closing: 2, stopped: 0 }[device.state?.cover_motion];
        initial.windowCovering = {
          type: 0,
          ...(movement === undefined ? {} : {
            operationalStatus: { global: movement, lift: movement, tilt: 0 },
          }),
        };
      }
      if (item.dimmable) initial.levelControl = {
        currentLevel: toMatterLevel(device.state?.brightness),
      };
      if (item.color) {
        const state = device.state ?? {};
        initial.colorControl = {
          currentHue: toMatterHue(state.hue ?? 0),
          currentSaturation: toMatterSaturation(state.saturation ?? 0),
          colorMode: typeof state.color_temp === "number" ? 2 : 0,
          ...(item.color === 22 ? {
            colorTemperatureMireds: Math.max(154, Math.min(500, state.color_temp ?? 235)),
            colorTempPhysicalMinMireds: 154,
            colorTempPhysicalMaxMireds: 500,
          } : {}),
        };
      }
      if (item.capability === "contact") initial.booleanState = {
        stateValue: device.state?.contact_open === true,
      };
      if (item.capability === "motion") initial.occupancySensing = {
        occupancy: {
          occupied: device.state?.motion_detected === true,
          occupancySensorType: 0,
          occupancySensorTypeBitmap: { pir: true, ultrasonic: false, physicalContact: false },
        },
      };
      if (item.capability === "cameraMotion") initial.occupancySensing = {
        occupancy: {
          occupied: device.state?.motion_detected === true,
          occupancySensorType: 0xff,
          occupancySensorTypeBitmap: {
            pir: false, ultrasonic: false, physicalContact: false,
          },
        },
      };
      if (item.capability === "temperature") initial.temperatureMeasurement = {
        measuredValue: toCentiCelsius(device.state?.temperature),
        minMeasuredValue: MIN_CENTI_CELSIUS,
        maxMeasuredValue: MAX_CENTI_CELSIUS,
        tolerance: 0,
      };
      if (item.capability === "humidity") initial.relativeHumidityMeasurement = {
        measuredValue: toCentiPercent(device.state?.humidity),
        minMeasuredValue: 0,
        maxMeasuredValue: MAX_CENTI_PERCENT,
        tolerance: 0,
      };
      const endpoint = new Endpoint(item.kind.with(...behaviors), {
        id: endpointId(item.key),
        ...initial,
      });
      record = { endpoint, device, capability: item.capability, dimmable: item.dimmable === true,
        color: item.color,
        channel: item.channel };
      await aggregator.add(endpoint);
      endpoints.set(item.key, record);
      console.info(`Added Matter endpoint ${name} (${item.key})`);
    } catch (error) {
      console.error(`Could not add Matter endpoint ${item.key}:`, error);
    }
  }
}

async function synchronize() {
  const devices = await request("/api/devices");
  const activeDevices = new Map();
  for (const device of devices) {
    activeDevices.set(identity(device), device);
    try {
      await addDevice(device);
    } catch (error) {
      console.error(`Could not add Matter endpoints for ${identity(device)}:`, error);
    }
    const baseKey = identity(device);
    const state = device.state;
    for (const [key, record] of endpoints) {
      if (key !== baseKey && !key.startsWith(`${baseKey}:`)) continue;
      record.device = device;
      const patch = { bridgedDeviceBasicInformation: { reachable: device.online === true } };
      if (record.pendingCommand && Date.now() - record.pendingCommand.sentAt > PENDING_STATE_TTL_MS) {
        record.pendingCommand = undefined;
      }
      if (record.capability === "onOff") {
        const currentOn = onState(device, record.channel);
        if (typeof currentOn === "boolean") {
          if (record.pendingCommand?.on === currentOn) delete record.pendingCommand.on;
          patch.onOff = { onOff: record.pendingCommand?.on ?? currentOn };
        }
      } else if (record.capability === "contact" && typeof state?.contact_open === "boolean") {
        patch.booleanState = { stateValue: state.contact_open };
      } else if ((record.capability === "motion" || record.capability === "cameraMotion") &&
          typeof state?.motion_detected === "boolean") {
        patch.occupancySensing = { occupancy: { occupied: state.motion_detected } };
      } else if (record.capability === "cover") {
        const movement = { opening: 1, closing: 2, stopped: 0 }[state?.cover_motion];
        if (movement !== undefined) {
          patch.windowCovering = {
            operationalStatus: { global: movement, lift: movement, tilt: 0 },
          };
        }
      } else if (record.capability === "temperature") {
        const measuredValue = toCentiCelsius(state?.temperature);
        if (measuredValue !== null) patch.temperatureMeasurement = { measuredValue };
      } else if (record.capability === "humidity") {
        const measuredValue = toCentiPercent(state?.humidity);
        if (measuredValue !== null) patch.relativeHumidityMeasurement = { measuredValue };
      }
      if (record.dimmable && typeof state?.brightness === "number") {
        const currentBrightness = Math.max(1, Math.min(100, Math.round(state.brightness)));
        if (record.pendingCommand?.brightness === currentBrightness) {
          delete record.pendingCommand.brightness;
        }
        patch.levelControl = {
          currentLevel: toMatterLevel(record.pendingCommand?.brightness ?? currentBrightness),
        };
      }
      if (record.color) {
        const hue = typeof state?.hue === "number" ? state.hue : undefined;
        const saturation = typeof state?.saturation === "number" ? state.saturation : undefined;
        const currentHue = record.pendingCommand?.hue ?? hue;
        const currentSaturation = record.pendingCommand?.saturation ?? saturation;
        if (typeof currentHue === "number" && typeof currentSaturation === "number") {
          if (record.pendingCommand?.hue === hue) delete record.pendingCommand.hue;
          if (record.pendingCommand?.saturation === saturation) {
            delete record.pendingCommand.saturation;
          }
          patch.colorControl = {
            currentHue: toMatterHue(currentHue),
            currentSaturation: toMatterSaturation(currentSaturation),
            colorMode: record.pendingCommand?.color_temp !== undefined ? 2 :
              record.pendingCommand?.hue !== undefined ||
                record.pendingCommand?.saturation !== undefined ? 0 :
                (typeof state?.color_temp === "number" ? 2 : 0),
          };
        }
        if (record.color === 22 && typeof state?.color_temp === "number") {
          if (record.pendingCommand?.color_temp === state.color_temp) {
            delete record.pendingCommand.color_temp;
          }
          patch.colorControl = {
            ...(patch.colorControl ?? {}),
            colorMode: record.pendingCommand?.color_temp !== undefined ? 2 :
              record.pendingCommand?.hue !== undefined ||
                record.pendingCommand?.saturation !== undefined ? 0 :
                (typeof state?.color_temp === "number" ? 2 : 0),
            colorTemperatureMireds: Math.max(154, Math.min(500,
              record.pendingCommand?.color_temp ?? state.color_temp)),
          };
        }
      }
      try {
        await record.endpoint.set(patch);
      } catch (error) {
        console.error(`Could not synchronize Matter endpoint ${key}:`, error);
      }
    }
  }
  for (const [key, record] of endpoints) {
    const device = activeDevices.get(identity(record.device));
    if (device) {
      const type = device.type;
      const supported = record.capability === "onOff"
        ? deviceClass(type, device.uiid) !== undefined &&
          record.color === (type === "COLOR_LIGHT" && [22, 59].includes(device.uiid)
            ? device.uiid : undefined) && dualR3RelayMode(device) && (record.channel === undefined
          ? !isDualR3(device) && record.dimmable === isDimmableType(type) &&
            channelSwitches(device) === undefined
          : isDualR3(device)
            ? Array.isArray(channelSwitches(device)) &&
              channelNumbers(device).includes(record.channel)
            : channelSwitches(device) === undefined ||
              channelNumbers(device).includes(record.channel))
        : record.capability === "contact"
          ? type === "CONTACT_SENSOR"
          : record.capability === "motion"
            ? type === "MOTION_SENSOR"
          : record.capability === "cameraMotion"
            ? type === "CAMERA"
          : record.capability === "cover"
            ? type === "WINDOW_COVERING" && device.uiid === 126
            : record.capability === "temperature"
              ? type === "TEMPERATURE_SENSOR" || type === "ENVIRONMENT_SENSOR" ||
                type === "THERMOSTAT" || type === "IR_REMOTE"
              : record.capability === "humidity"
                ? type === "HUMIDITY_SENSOR" || type === "ENVIRONMENT_SENSOR" ||
                  (type === "TEMPERATURE_SENSOR" && key.endsWith(":humidity")) ||
                  type === "THERMOSTAT" || type === "IR_REMOTE"
                : false;
      if (supported) continue;
    }
    try {
      await record.endpoint.close();
      endpoints.delete(key);
      console.info(`Removed Matter endpoint for unregistered device ${key}`);
    } catch (error) {
      console.error(`Could not remove Matter endpoint ${key}:`, error);
    }
  }
}

await synchronize();
await server.start();
if (!server.lifecycle.isCommissioned) {
  const { qrPairingCode, manualPairingCode } = server.state.commissioning.pairingCodes;
  console.info(QrCode.get(qrPairingCode));
  console.info(`QR Code URL: https://project-chip.github.io/connectedhomeip/qrcode.html?data=${qrPairingCode}`);
  console.info(`Manual pairing code: ${manualPairingCode}`);
} else {
  console.info("Matter bridge is commissioned; waiting for controllers to connect.");
}
console.info(`FIREALEXA Matter bridge started on UDP ${port}.`);
let syncTimer;
let closing = false;
async function synchronizeLoop() {
  if (closing) return;
  try {
    await synchronize();
  } catch (error) {
    console.error("Matter bridge sync failed:", error);
    if (error instanceof ApiConnectionError) await markEndpointsUnreachable();
  }
  if (!closing) syncTimer = setTimeout(synchronizeLoop, 3000);
}

async function shutdown() {
  if (closing) return;
  closing = true;
  clearTimeout(syncTimer);
  await server.close();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
syncTimer = setTimeout(synchronizeLoop, 3000);
