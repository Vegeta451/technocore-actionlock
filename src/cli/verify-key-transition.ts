import { open } from "node:fs/promises";
import { verifyKeyTransition } from "../server/key-transition";

const args = process.argv.slice(2);
if (args.length !== 2) throw new Error("Usage: npm run verify:transition -- <transition.json> <trusted-old-key-id>");
const file = await open(args[0], "r");
let value: unknown;
try {
  const buffer = Buffer.alloc(16_385);
  let length = 0;
  while (length < buffer.length) {
    const { bytesRead } = await file.read(buffer, length, buffer.length - length, null);
    if (!bytesRead) break;
    length += bytesRead;
  }
  if (length > 16_384) throw new Error("Key transition exceeds 16 KiB");
  value = JSON.parse(buffer.subarray(0, length).toString("utf8"));
} finally {
  await file.close();
}
const result = verifyKeyTransition(value, args[1]);
console.log(JSON.stringify({ ...result, notice: "Signatures prove a planned handover from the pinned old key, not latest-key status, revocation, compromise recovery, or an independently witnessed time." }, null, 2));
if (!result.valid) process.exitCode = 1;
