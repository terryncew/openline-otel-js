import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import { canonicalJson, parseJsonStrict } from "./canonical.mjs";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_128 = /^[0-9a-f]{128}$/;

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest();
}

export function sha256Canonical(value) {
  return sha256Bytes(canonicalJson(value)).toString("hex");
}

export function privateKeyFromSeed(seed) {
  const bytes = Buffer.isBuffer(seed) ? seed : Buffer.from(seed, "hex");
  if (bytes.length !== 32) throw new TypeError("Ed25519 seed must be exactly 32 bytes");
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, bytes]),
    format: "der",
    type: "pkcs8",
  });
}

export function publicKeyHex(key) {
  const der = createPublicKey(key).export({ format: "der", type: "spki" });
  if (!Buffer.from(der).subarray(0, SPKI_ED25519_PREFIX.length).equals(SPKI_ED25519_PREFIX)) {
    throw new TypeError("key is not an Ed25519 key");
  }
  return Buffer.from(der).subarray(-32).toString("hex");
}

export function publicKeyFromHex(value) {
  if (!HEX_64.test(value)) throw new TypeError("public key must be 32-byte lowercase hex");
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(value, "hex")]),
    format: "der",
    type: "spki",
  });
}

export function signReceipt(body, privateKey) {
  if (Object.hasOwn(body, "payload_hash") || Object.hasOwn(body, "signature")) {
    throw new TypeError("receipt body must not contain envelope fields");
  }
  const payload = canonicalJson(body);
  return {
    ...body,
    payload_hash: sha256Bytes(payload).toString("hex"),
    signature: {
      algorithm: "Ed25519",
      public_key: publicKeyHex(privateKey),
      value: ed25519Sign(null, payload, privateKey).toString("hex"),
    },
  };
}

export function verifyReceipt(receipt, { validateProfile } = {}) {
  try {
    if (validateProfile) validateProfile(receipt);
    const { payload_hash: payloadHash, signature, ...body } = receipt;
    if (!HEX_64.test(payloadHash) || signature?.algorithm !== "Ed25519") return false;
    if (!HEX_64.test(signature.public_key) || !HEX_128.test(signature.value)) return false;
    const payload = canonicalJson(body);
    if (sha256Bytes(payload).toString("hex") !== payloadHash) return false;
    return ed25519Verify(
      null,
      payload,
      publicKeyFromHex(signature.public_key),
      Buffer.from(signature.value, "hex"),
    );
  } catch {
    return false;
  }
}

export function verifyReceiptJson(text, options = {}) {
  try {
    return verifyReceipt(parseJsonStrict(text), options);
  } catch {
    return false;
  }
}
