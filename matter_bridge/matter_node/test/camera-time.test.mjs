import test from "node:test";
import assert from "node:assert/strict";
import { Status } from "@matter/main/types";
import { CameraClock, loadCameraClock } from "../camera-time.mjs";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

test("UTC starts unknown and advances from administrator time using elapsed time", async () => {
  let mono = 100n;
  const saved = [];
  const clock = new CameraClock({ monotonic: () => mono, persist: async value => saved.push(value) });
  assert.equal(clock.now(), null);
  await clock.set({ utcTime: 1_000_000n, granularity: 4 });
  mono += 20_123n;
  assert.equal(clock.now(), 1_020_123n);
  assert.equal(clock.granularity, 3);
  assert.deepEqual(saved, [1_000_000n]);
});

test("last-known-good UTC never moves backwards and is not used as current time after restart", async () => {
  const saved = [];
  const clock = new CameraClock({ lastKnownGood: 5_000_000n, persist: async value => saved.push(value) });
  assert.equal(clock.now(), null);
  await clock.set({ utcTime: 1_000_000n, granularity: 3 });
  assert.equal(clock.lastKnownGood, 5_000_000n);
  assert.deepEqual(saved, [5_000_000n]);
});

test("invalid time and persistence failures do not claim synchronization", async () => {
  const clock = new CameraClock({ persist: async () => { throw new Error("private storage path"); } });
  for (const request of [{ utcTime: -1n, granularity: 3 }, { utcTime: 10n, granularity: 0 },
    { utcTime: Number.MAX_SAFE_INTEGER + 1, granularity: 3 }, { utcTime: 1n << 64n, granularity: 3 }]) {
    await assert.rejects(clock.set(request), error => error.code === Status.ConstraintError);
  }
  await assert.rejects(clock.set({ utcTime: 1n, granularity: 3 }), error =>
    error.code === Status.Failure && !error.message.includes("private storage path"));
  assert.equal(clock.now(), null);
});

test("UTC high-water survives restart but corrupted storage is not silently reset", async t => {
  const directory = await mkdtemp(join(tmpdir(), "firealexa-clock-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "clock.json");
  const clock = await loadCameraClock(path);
  await clock.set({ utcTime: 1000000n, granularity: 3 });
  assert.equal(JSON.parse(await readFile(path, "utf8")).lastKnownGood, "1000000");
  if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);
  const restarted = await loadCameraClock(path);
  assert.equal(restarted.lastKnownGood, 1000000n);
  assert.equal(restarted.now(), null);
  await writeFile(path, "corrupt");
  await assert.rejects(loadCameraClock(path), /Unable to load UTC storage/);
});
