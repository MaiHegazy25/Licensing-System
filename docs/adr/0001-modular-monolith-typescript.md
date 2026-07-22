# ADR-0001: Modular monolith on TypeScript/Node

- Status: Accepted
- Date: 2026-07-22

## Context
Greenfield repo (only a README existed). The brief prefers a modular monolith
unless scale justifies microservices, and requires a build that we can actually
compile and test. The execution environment has Node 22, Python 3.11 and
PostgreSQL 16 available but **no .NET SDK**.

## Decision
Build a **modular monolith in TypeScript (Node 22)** with npm workspaces:
`shared`, `server`, `sdk`. Domain is isolated from infra via ports/adapters.

## Consequences
- (+) Compiles and tests in-environment; shared types across server, SDK, and
  the future React portals.
- (+) Node's built-in `crypto` provides Ed25519 — no third-party crypto lib.
- (−) If a first product is C#/C++/Java, the SDK contract must be re-implemented
  natively. The SDK is specified as a contract (see `docs/` + SDK README) so
  native ports mirror the same interface and token format.
- Revisit if org boundaries or scale demand service extraction; the module seams
  make that possible without a rewrite.
