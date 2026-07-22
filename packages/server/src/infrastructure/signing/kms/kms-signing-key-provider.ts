/**
 * SigningKeyProvider backed by a KMS/HSM. The active signer delegates the
 * signature to the KMS (private key stays in the vault); verification uses
 * PUBLIC keys fetched once at startup and cached (so PublicKeyStore.get stays
 * synchronous). Adding a new `kid` to the KMS + trust list is a full rotation.
 */
import type { KeyObject } from "node:crypto";
import type {
  Ed25519Signer,
  PublicKeyStore,
} from "@vehiclevo/licensing-shared";
import type { SigningKeyProvider } from "../key-provider.js";
import type { KmsSignerClient } from "./kms-signer-client.js";

export class KmsSigningKeyProvider implements SigningKeyProvider {
  private constructor(
    private readonly client: KmsSignerClient,
    private readonly activeKid: string,
    private readonly publicKeys: Map<string, KeyObject>,
  ) {}

  /**
   * Fetches and caches the public keys for all trusted kids up front, so
   * verification is synchronous thereafter.
   */
  static async create(client: KmsSignerClient, activeKid: string): Promise<KmsSigningKeyProvider> {
    const kids = client.trustedKeyIds();
    if (!kids.includes(activeKid)) {
      throw new Error(`active signing key '${activeKid}' is not among the KMS trusted keys`);
    }
    const publicKeys = new Map<string, KeyObject>();
    for (const kid of kids) {
      publicKeys.set(kid, await client.getPublicKey(kid));
    }
    return new KmsSigningKeyProvider(client, activeKid, publicKeys);
  }

  activeSigner(): Ed25519Signer {
    return {
      kid: this.activeKid,
      // The signature happens inside the KMS; no private key here.
      sign: (data) => this.client.sign(this.activeKid, data),
    };
  }

  publicKeyStore(): PublicKeyStore {
    return { get: (kid) => this.publicKeys.get(kid) };
  }

  trustedKeyIds(): string[] {
    return [this.activeKid, ...[...this.publicKeys.keys()].filter((k) => k !== this.activeKid)];
  }
}
