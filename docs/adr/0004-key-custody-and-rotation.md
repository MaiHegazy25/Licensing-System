# ADR-0004: Key custody in KMS/HSM with kid-based rotation

- Status: Accepted
- Date: 2026-07-22

## Context
Private signing keys are the highest-value asset. If they leak, every license
can be forged. The brief mandates KMS/HSM custody and rotation.

## Decision
- Private keys are generated and held in a managed **KMS/HSM** (Azure Key Vault
  / AWS KMS / on-prem PKCS#11). Signing happens **inside** the KMS; the raw key
  never enters the app process.
- The app exposes a `SigningKeyProvider` port. Production = KMS adapter; a
  **`local` provider (dev only)** loads gitignored PEMs and is **blocked in
  production** by config validation.
- Clients ship a trust store of **public** keys keyed by `kid` (current + next).
- **Rotation runbook** _(P6)_: (1) create new kid in KMS; (2) publish its public
  key to clients; (3) flip active signer to new kid; (4) retire old kid after
  all its tokens expire. **Compromise**: revoke the kid immediately, force
  re-issue, rotate; treat all tokens under that kid as suspect.

## Implementation status
- The `SigningKeyProvider` port has two adapters: `LocalKeyProvider` (dev; PEMs
  on disk, blocked in production) and `KmsSigningKeyProvider` (production).
- Reference KMS adapter: **Azure Key Vault** via its REST API (no cloud SDK),
  using **EdDSA/Ed25519** so the token format is unchanged. Signing happens in
  the vault; the app fetches only public keys (cached at startup for sync
  verification). `SIGNING_PROVIDER=kms` selects it; `KMS_KEYS` maps each `kid`
  to a vault key name+version. AAD auth via client-credentials.
- AWS KMS / GCP note: AWS KMS and GCP KMS do not offer Ed25519 signing today;
  targeting them would mean either Azure Managed HSM (Ed25519) or switching the
  token to an ECDSA/RSA `alg` behind the same `keyId` mechanism.

## Consequences
- (+) A DB or app-server compromise does not expose signing keys.
- (+) Rotation is non-breaking; compromise is contained to one kid.
- (−) Requires KMS integration and a signing round-trip per issue (cache/pool).
