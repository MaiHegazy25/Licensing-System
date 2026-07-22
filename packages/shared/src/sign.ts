/**
 * Assemble + Ed25519-sign a license token from claims and a private key.
 *
 * This is a pure function over (claims, kid, signer). The SERVER's signing
 * service calls it — in production the `signer` is backed by KMS/HSM and the
 * raw private key never enters process memory. The SDK never imports this.
 */
import type { KeyObject } from "node:crypto";
import { canonicalize } from "./canonical.js";
import { signEd25519 } from "./crypto.js";
import {
  base64UrlEncode,
  signingInput,
  LICENSE_TOKEN_ALG,
  LICENSE_TOKEN_TYP,
  type LicenseClaims,
  type LicenseTokenHeader,
} from "./token.js";

/** Abstracts the actual signing operation so it can be a local key or a KMS call. */
export interface Ed25519Signer {
  readonly kid: string;
  sign(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** Convenience signer backed by an in-memory private KeyObject (dev/test). */
export function localSigner(kid: string, privateKey: KeyObject): Ed25519Signer {
  return {
    kid,
    sign: (data) => signEd25519(data, privateKey),
  };
}

export async function signLicenseToken(
  claims: LicenseClaims,
  signer: Ed25519Signer,
): Promise<string> {
  const header: LicenseTokenHeader = {
    alg: LICENSE_TOKEN_ALG,
    typ: LICENSE_TOKEN_TYP,
    kid: signer.kid,
  };
  const headerB64 = base64UrlEncode(
    new TextEncoder().encode(canonicalize(header)),
  );
  const payloadB64 = base64UrlEncode(
    new TextEncoder().encode(canonicalize(claims)),
  );
  const signature = await signer.sign(signingInput(headerB64, payloadB64));
  return `${headerB64}.${payloadB64}.${base64UrlEncode(signature)}`;
}
