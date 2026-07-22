/**
 * Ed25519 primitives via Node's built-in `crypto` (libcrypto under the hood).
 * No custom cryptography — we only orchestrate standard EdDSA sign/verify.
 *
 * The SDK uses only `verifyEd25519` with an embedded PUBLIC key. Private keys
 * never appear in client builds.
 */
import {
  sign as nodeSign,
  verify as nodeVerify,
  createHash,
  createPublicKey,
  createPrivateKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";

/**
 * Stable, non-reversible binding value for a device id. Computed identically on
 * the server (when issuing a device-bound/offline token) and in the SDK (when
 * checking a token belongs to this device). Not a secret — just a binding.
 */
export function hashDeviceBinding(deviceId: string): string {
  return createHash("sha256").update(`vv-device:${deviceId}`).digest("hex");
}

export function publicKeyFromPem(pem: string): KeyObject {
  return createPublicKey(pem);
}

export function privateKeyFromPem(pem: string): KeyObject {
  return createPrivateKey(pem);
}

/** Ed25519 sign. `key` must be a private key. */
export function signEd25519(data: Uint8Array, key: KeyObject): Uint8Array {
  // For Ed25519 the algorithm argument must be null.
  return new Uint8Array(nodeSign(null, Buffer.from(data), key));
}

/** Ed25519 verify. `key` must be a public key. Never throws on bad sig — returns false. */
export function verifyEd25519(
  data: Uint8Array,
  signature: Uint8Array,
  key: KeyObject,
): boolean {
  try {
    return nodeVerify(null, Buffer.from(data), key, Buffer.from(signature));
  } catch {
    return false;
  }
}

export interface GeneratedKeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

/** Dev/test key generation. Production keys are created in KMS/HSM, not here. */
export function generateEd25519KeyPair(): GeneratedKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}
