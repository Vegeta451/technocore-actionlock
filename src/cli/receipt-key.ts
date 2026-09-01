import { resolve } from "node:path";
import { loadOrCreateReceiptSigner } from "../server/public-receipt";

const stateDirectory = resolve(process.env.ACTIONLOCK_STATE_DIR ?? "./data/actionlock");
const path = resolve(
  process.env.ACTIONLOCK_RECEIPT_KEY_PATH ?? `${stateDirectory}/receipt-signing-key.json`,
);
const signer = await loadOrCreateReceiptSigner(path);

console.log(JSON.stringify({
  algorithm: "Ed25519",
  keyId: signer.keyId,
  publicKey: signer.publicKey,
  keyPath: path,
}, null, 2));
