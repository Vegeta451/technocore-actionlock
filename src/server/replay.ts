import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

export interface ReplayStore {
  consume(grantId: string, expiresAt: number): Promise<boolean>;
}

export class FileReplayStore implements ReplayStore {
  constructor(private readonly directory: string) {}

  async consume(grantId: string, expiresAt: number): Promise<boolean> {
    if (!/^[a-f0-9]{32}$/.test(grantId)) return false;
    await mkdir(this.directory, { recursive: true });
    const name = createHash("sha256").update(grantId).digest("hex");
    try {
      await writeFile(
        join(this.directory, `${name}.json`),
        `${JSON.stringify({ version: 1, grantId, expiresAt, consumedAt: new Date().toISOString() })}\n`,
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      );
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
      throw error;
    }
  }
}
