import { readFile } from "node:fs/promises";
import { verifyPublicReceipt, verifyPublicReceiptBundle } from "../server/public-receipt";

const [receiptPath, expectedKeyId] = process.argv.slice(2);
if (!receiptPath) {
  throw new Error("Usage: npm run verify:receipt -- <receipt.json> [expected-key-id]");
}

const receipt = JSON.parse(await readFile(receiptPath, "utf8")) as unknown;
const options = expectedKeyId ? { expectedKeyIds: [expectedKeyId] } : {};
const isBundle = Boolean(
  receipt && typeof receipt === "object" && "approval" in receipt && "execution" in receipt,
);
const result = isBundle ? verifyPublicReceiptBundle(receipt, options) : verifyPublicReceipt(receipt, options);
console.log(JSON.stringify(result, null, 2));
if (!result.valid) process.exitCode = 1;
