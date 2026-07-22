# ADR-0003: Separate signed token from mutable server state

- Status: Accepted
- Date: 2026-07-22

## Context
Some license facts are fixed at issue time (entitlements); others change after
issue (revocation, suspension, seat leases). Baking mutable facts into a signed
token would make them un-changeable without re-issuing; omitting a liveness
check would let revoked licenses run forever offline.

## Decision
The **signed token** carries only immutable claims + validity/offline windows.
**Mutable truth** (revocation, suspension, current leases, last-seen) lives in
server state. The token has a **short TTL**; `offlineUntil` bounds no-contact
operation; online `/validate` is authoritative for mutable state.

## Consequences
- (+) Revocation propagates by token expiry / next online check without needing
  to reach the device directly.
- (+) Offline still works within a bounded, signed window.
- (−) Requires the client to come online periodically; tuned via TTL +
  `offlineUntil` + `gracePeriodSeconds` per license.
