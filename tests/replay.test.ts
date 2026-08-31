import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { FileReplayStore } from "../src/server/replay";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("persistent replay store", () => {
  it("allows exactly one concurrent consumer and survives a new store instance", async () => {
    const directory = await mkdtemp(join(tmpdir(), "actionlock-replay-"));
    directories.push(directory);
    const grantId = "a".repeat(32);
    const results = await Promise.all(
      Array.from({ length: 12 }, () => new FileReplayStore(directory).consume(grantId, 999_999)),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await new FileReplayStore(directory).consume(grantId, 999_999)).toBe(false);
  });
});
