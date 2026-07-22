/**
 * Port to a managed KMS/HSM signing backend.
 *
 * The whole point: the private signing key never enters this process. We ask the
 * KMS to sign bytes with a key identified by our `kid`, and we fetch only the
 * PUBLIC key for local verification. Concrete adapters (Azure Key Vault, AWS
 * KMS Managed-HSM, PKCS#11) implement this port.
 */
import type { KeyObject } from "node:crypto";

export interface KmsSignerClient {
  /** All kids this client can sign/verify with (active + previous, for rotation). */
  trustedKeyIds(): string[];
  /** Sign `data` with the key identified by `kid` (Ed25519 / EdDSA), inside the KMS. */
  sign(kid: string, data: Uint8Array): Promise<Uint8Array>;
  /** Fetch the PUBLIC key for `kid` so tokens can be verified locally. */
  getPublicKey(kid: string): Promise<KeyObject>;
}
