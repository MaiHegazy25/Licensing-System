/**
 * Development/test signing key provider. Loads Ed25519 keypairs from a directory
 * of the form  <dir>/<kid>.public.pem  and  <dir>/<kid>.private.pem.
 *
 * DEV ONLY. In production use a KMS/HSM provider so private keys never touch
 * this process. The private key material loaded here is gitignored and must
 * never be committed.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { KeyObject } from "node:crypto";
import {
  localSigner,
  privateKeyFromPem,
  publicKeyFromPem,
  type Ed25519Signer,
  type PublicKeyStore,
} from "@vehiclevo/licensing-shared";
import type { SigningKeyProvider } from "./key-provider.js";

interface KeyEntry {
  kid: string;
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export class LocalKeyProvider implements SigningKeyProvider {
  private readonly keys = new Map<string, KeyEntry>();
  private readonly activeKid: string;

  private constructor(entries: KeyEntry[], activeKid: string) {
    for (const e of entries) this.keys.set(e.kid, e);
    if (!this.keys.has(activeKid)) {
      throw new Error(`active signing key '${activeKid}' not found among loaded keys`);
    }
    this.activeKid = activeKid;
  }

  /** Load all keypairs from a directory; `activeKid` selects the signer. */
  static fromDirectory(dir: string, activeKid: string): LocalKeyProvider {
    const files = readdirSync(dir);
    const kids = new Set(
      files
        .filter((f) => f.endsWith(".public.pem"))
        .map((f) => f.replace(/\.public\.pem$/, "")),
    );
    const entries: KeyEntry[] = [];
    for (const kid of kids) {
      const publicKey = publicKeyFromPem(
        readFileSync(join(dir, `${kid}.public.pem`), "utf8"),
      );
      const privateKey = privateKeyFromPem(
        readFileSync(join(dir, `${kid}.private.pem`), "utf8"),
      );
      entries.push({ kid, publicKey, privateKey });
    }
    return new LocalKeyProvider(entries, activeKid);
  }

  /** In-memory construction (tests / demo without disk). */
  static fromPems(
    entries: { kid: string; publicKeyPem: string; privateKeyPem: string }[],
    activeKid: string,
  ): LocalKeyProvider {
    return new LocalKeyProvider(
      entries.map((e) => ({
        kid: e.kid,
        publicKey: publicKeyFromPem(e.publicKeyPem),
        privateKey: privateKeyFromPem(e.privateKeyPem),
      })),
      activeKid,
    );
  }

  activeSigner(): Ed25519Signer {
    const entry = this.keys.get(this.activeKid)!;
    return localSigner(entry.kid, entry.privateKey);
  }

  publicKeyStore(): PublicKeyStore {
    return { get: (kid) => this.keys.get(kid)?.publicKey };
  }

  trustedKeyIds(): string[] {
    return [this.activeKid, ...[...this.keys.keys()].filter((k) => k !== this.activeKid)];
  }
}
