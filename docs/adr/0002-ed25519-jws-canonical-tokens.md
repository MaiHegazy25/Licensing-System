# ADR-0002: Ed25519 + JWS-style tokens with canonical JSON

- Status: Accepted
- Date: 2026-07-22

## Context
Licenses must be signed with asymmetric crypto, verifiable offline by the client,
and support key rotation. We must not invent cryptography.

## Decision
- **Ed25519 (EdDSA)** signatures via Node `crypto`. Deterministic, small keys,
  misuse-resistant, no parameter choices to get wrong (vs. RSA/ECDSA nonces).
- **JWS-like compact envelope**: `b64url(header).b64url(payload).b64url(sig)`
  with `header = {alg:"EdDSA", typ:"license+jws", kid}`.
- **Canonical JSON** (RFC 8785 spirit: sorted keys, no insignificant
  whitespace, non-finite rejected) for the payload so the client re-serializes
  to identical bytes before verifying.
- `kid` selects the public key → rotation without breaking old tokens.

## Alternatives considered
- Raw JWT libs: acceptable, but canonical payload + explicit `schemaVersion`
  gives us stable versioning and avoids ambiguity in claim encoding.
- RSA: larger keys/signatures, nonce-free but more footguns. Rejected.

## Consequences
- (+) Offline-verifiable, tamper-evident, rotation-ready.
- (−) We own a small canonicalization implementation (tested for stability).
