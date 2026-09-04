import { resolve } from "node:path";
import { prepareKeyTransition, verifyKeyTransition } from "../server/key-transition";

const args = process.argv.slice(2);
if (args.length !== 3) throw new Error("Usage: npm run receipt:transition -- <old-key.json> <new-key.json> <new-transition.json>");
const [previousPath, nextPath, outputPath] = args.map((path) => resolve(path));
const transition = await prepareKeyTransition(previousPath, nextPath, outputPath);
console.log(JSON.stringify({
  ...verifyKeyTransition(transition, transition.statement.previous.keyId),
  outputPath,
  activated: false,
  notice: "Public transition prepared. No key, gateway configuration, or trust pin was changed. Verify before manually activating the new key between calls.",
}, null, 2));
