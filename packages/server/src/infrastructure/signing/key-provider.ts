/**
 * Signing key abstraction.
 *
 * Production: a KMS/HSM-backed provider whose `activeSigner()` performs the
 * Ed25519 signature INSIDE the KMS — the private key never enters this process.
 * Development: `LocalKeyProvider` loads PEM keypairs from disk (gitignored).
 *
 * Either way the server exposes a public-key store (current + previous kids) so
 * it can verify its own tokens and so rotation is a matter of adding a new kid.
 */
import type { Ed25519Signer } from "@vehiclevo/licensing-shared";
import type { PublicKeyStore } from "@vehiclevo/licensing-shared";

export interface SigningKeyProvider {
  /** The signer used for NEWLY issued tokens. */
  activeSigner(): Ed25519Signer;
  /** Verifies tokens signed by the active key and any still-trusted prior keys. */
  publicKeyStore(): PublicKeyStore;
  /** All kids currently trusted for verification (active first). */
  trustedKeyIds(): string[];
}
