# Threat Model — Vehiclevo Licensing Platform

Scope: the licensing backend, signing keys, activation flow, and the client SDK.
Methodology: enumerate assets, then walk the specific threats called out in the
brief. Each threat lists the mitigation and its **current status**.

## Assets
- Private signing keys (highest value).
- Activation codes (pre-activation bearer secrets).
- License tokens (signed entitlement proofs).
- Server state (revocation, seats, audit).
- Admin credentials / sessions.
- Customer PII (minimal by design).

## Trust boundaries
- Client device is **untrusted** — anything shipped to it (SDK, public keys,
  cached token) is visible to an attacker.
- The backend and KMS are the trust anchors.
- Network is untrusted → TLS everywhere.

## Threats & mitigations

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T1 | **Copied license file** to another machine | Token is signed + time-bounded; `offlineUntil` limits reuse window; device activation records cap seats; node-locked binding available | ✅ token/seat parts; ⏳ device-binding enforcement |
| T2 | **Cloned VM** shares one activation | Seat limit enforced server-side per active device; floating leases expire without heartbeat _(planned)_ | ✅ seat cap; ⏳ floating |
| T3 | **Clock manipulation** (roll back to dodge expiry) | SDK records highest server time; local time earlier than that beyond skew ⇒ `clock_tampered`, deny | ✅ implemented + tested |
| T4 | **Leaked activation code** | High-entropy codes; only HMAC(pepper) hash stored; single/max-use enforced ATOMICALLY (race-free conditional update); per-IP rate limiting on public endpoints; revocable | ✅ (rate limit is per-instance baseline; distributed limiter ⏳) |
| T5 | **Stolen token** | Short TTL forces re-validation; revocation kills it server-side; audience/issuer bound; tokenId for tracing; `/validate` refuses devices without an ACTIVE activation (a deactivated device cannot renew) | ✅ implemented |
| T6 | **Token tampering** (inject features) | Ed25519 signature over canonical payload; any edit ⇒ `bad_signature` | ✅ implemented + tested |
| T7 | **Compromised admin account** | RBAC least privilege, admin auth isolated, audit log of admin actions; MFA via IdP _(planned)_ | ⏳ minimal key today; audit ✅ |
| T8 | **API abuse / enumeration / brute force** | Opaque UUID ids; uniform error shapes; per-IP fixed-window rate limiting on all public endpoints (429); security-event log records rate-limit hits and failed admin/customer/deactivate auth; constant-time secret compares | ✅ baseline (per-instance limiter; shared-store limiter ⏳) |
| T9 | **Database compromise** | No plaintext codes (hash only); no private keys in DB (KMS only); encryption at rest _(deployment)_; PII minimized | ✅ code/key handling; ⏳ at-rest config |
| T10 | **Signing-key compromise** | Keys only in KMS/HSM; `kid` rotation; revoke compromised kid, re-issue; clients trust current+next | ✅ design + rotation mechanics; ⏳ KMS provider |
| T11 | **Replay** (reuse activation/validate) | tokenId (jti), single-use codes, idempotent re-activation by device, nonce/rate limits _(planned)_ | ✅ partial; ⏳ nonce |
| T12 | **Downgrade / short network blip blocks user** | Offline fallback within window; never hard-exit on transient network error | ✅ implemented + tested |
| T13 | **Trial farming** (repeated free trials) | One trial per (product, device) enforced by a DB unique constraint (race-proof); trial tokens device-bound; rate limiting on /trial/start. HONEST LIMIT: the guard keys on the client-derived device id — wiping/forging it defeats the guard; this raises cost, it cannot fully prevent | ✅ baseline |

## Residual risk (acknowledged)
- A fully attacker-controlled device can patch the SDK. We raise cost and make
  tampering evident; we do not claim unbreakable DRM.
- Until the KMS provider and rate limiting land, T7/T8/T10 mitigations are
  partially in design. These are tracked in the phase plan and marked in code.

## Privacy & retention _(policy — to finalize with company input)_
- Collect a **derived, salted device id**, never raw MAC/serial alone.
- Retain audit/security events per legal requirement (proposed 13 months hot,
  then cold archive). Provide customer device list + self-service deactivation.
- Incident response + key-compromise runbooks: see ADR-0004 and P6.
