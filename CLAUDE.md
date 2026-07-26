# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install                       # install all workspaces
npm test                          # vitest, all packages (Postgres tests auto-skip)
npx vitest run path/to/file.test.ts               # single test file
TEST_DATABASE_URL=postgres://... npm test         # include Postgres integration tests
npx tsc --build                   # typecheck + compile shared/server/sdk (composite build)
npm run build -w @vehiclevo/licensing-admin-web    # typecheck + bundle admin SPA
npm run build -w @vehiclevo/licensing-customer-web # typecheck + bundle customer SPA

# run the server locally (in-memory repos unless DATABASE_URL is set)
node --loader ts-node/esm packages/server/scripts/keygen.ts key-2026-01 ./keys/local   # dev signing keypair (gitignored)
cp .env.example .env              # then set ACTIVE_SIGNING_KEY_ID, ACTIVATION_CODE_PEPPER, ADMIN_API_KEY
npm start -w @vehiclevo/licensing-server

docker compose up -d db           # local Postgres; migrations auto-apply on server startup
npm run migrate -w @vehiclevo/licensing-server     # or apply them explicitly
```

Test quirks that matter:
- `vitest.config.ts` aliases `@vehiclevo/licensing-*` to **TypeScript source**, so tests run without building. The `tsc --build` outputs (`dist/`) exclude `__tests__/` — a test importing a symbol must ensure it's exported from the package's `src/index.ts`.
- Postgres tests (`postgres.test.ts`) are gated on `TEST_DATABASE_URL` and start by **dropping the schema**, then re-running all migrations — point it only at a throwaway database.
- Several test files set `process.env` (ADMIN_API_KEY, ADMIN_API_KEYS, RATE_LIMIT_MAX, ...) in `beforeAll`; when adding a server test file, set/delete the env keys you depend on explicitly rather than assuming defaults.

## Architecture

npm-workspaces monorepo: `packages/shared` (crypto + token format), `packages/server` (backend), `packages/sdk` (client SDK embedded in products), `packages/admin-web` and `packages/customer-web` (React/Vite SPAs). `docs/adr/` records the load-bearing decisions — read ADR-0002/0003/0004/0005 before changing token format, key custody, or authorization.

### The central invariant: signed token vs server state (ADR-0003)

A license produces two kinds of truth:
- **Signed token** (`shared/src/token.ts`, Ed25519 over canonical JSON, JWS-like, `kid` header for rotation): immutable entitlements — features, edition, seat max, validity/offline windows, optional `deviceBinding`. Verifiable fully offline by the SDK against embedded public keys.
- **Server-side mutable state** (Postgres/in-memory repos): revocation, suspension, activations/seats, floating leases, trial registry. Only online `/validate` is authoritative for these.

Online tokens get a short TTL (forces periodic re-validation so revocation propagates); offline-activation tokens are long-lived but device-bound. If you add a claim, bump `schemaVersion` and remember both server and SDK re-serialize through `canonicalize()` — payload bytes must be identical on both sides.

### Server layering (strict)

`domain/` (no imports from other layers: state machine in `license.ts`, RBAC matrix in `rbac.ts`) ← `application/` (use cases in `licensing-service.ts`; **ports** in `ports.ts` + `auth.ts` + `token-issuer.ts`) ← `infrastructure/` (adapters) ← `api/http.ts` (transport only) ← `container.ts` (composition root).

`container.ts` is where implementations are selected, all by config/env:
- Persistence: `DATABASE_URL` set → Postgres adapters, else in-memory (behaviorally faithful, used by most tests).
- Signing: `SIGNING_PROVIDER=local` (dev PEMs on disk, blocked in production by `config.ts`) vs `kms` (Azure Key Vault over REST, private keys never in-process) — built async in `main.ts` via `buildKeyProvider`, injected into `buildContainer`.
- Admin auth: `AUTH_MODE=apikey` vs `oidc` behind the same `PrincipalResolver` port; customer portal auth is a separate `CustomerPrincipalResolver`.

### Concurrency: enforce counts in the repository, never check-then-act in the service

Every quantity cap is enforced atomically at the adapter layer; the Postgres adapters are the reference semantics:
- Seats: `createIfUnderSeatLimit` — `SELECT … FOR UPDATE` on the license row, then count+insert.
- Floating leases: `acquire` — same row lock; expired leases auto-reclaim (no cleanup job).
- Activation codes: `consumeUse` — conditional `UPDATE … WHERE used_activations < max_activations`, with compensating `releaseUse` if the follow-up insert fails.
- Trials: `UNIQUE (product_id, device_id)`; on conflict the loser retires its orphan license and resumes the winner's.
- Admin license edits: optimistic `version` column.

Concurrency tests in `postgres.test.ts` race N parallel calls and assert exact winner counts — mirror that pattern when adding capped resources.

### Authorization

Routes require **permissions, not roles** (`authorize(req, "license:revoke")`); the role→permission matrix lives only in `domain/rbac.ts`. The SPAs mirror it via `/admin/me` purely to hide controls — the server is the sole enforcer. Customer endpoints (`/api/v1/customer/*`) are scoped by `requireOwnedLicense`, which returns NOT_FOUND (never 403) on cross-customer access to avoid existence leaks. Bootstrap client endpoints (activate/trial/offline/floating) are unauthenticated but rate-limited (`enforceRateLimit`). `/validate` and `/deactivate` require **proof-of-possession** (`requireTokenProof`): a validly signed token whose `deviceBinding` matches the calling device — expired tokens are accepted (possession is what is proven), unbound ones never are, and the licenseId comes from the verified claims rather than the body. Every token the server issues is device-bound, so a copied state file is useless elsewhere. Request bodies are validated against the JSON Schemas in `api/schemas.ts` before handlers run (`req.body as X` is only safe because of them).

### Time

There is no `Date.now()` in domain/application code — everything takes a `Clock` port (`FakeClock` in tests, advanced/rewound to test expiry, grace, lease reclaim, clock rollback). Timestamps are **epoch seconds** (BIGINT in Postgres), not milliseconds or timestamptz.

### SDK design rules

The SDK fails **safe**: every error path leaves `snapshot.ok === false` and `hasFeature()` false; network failures fall back to the cached signed token within its offline window (never hard-fail on a blip). It detects clock rollback via the highest server-issued time seen, and enforces `deviceBinding` centrally in `snapshotFromToken`. All dependencies (`http`, `store`, `clock`) are injected — tests script the transport. Errors carry stable codes (`LicensingErrorCode`) plus user-safe messages. The SDK must never import server internals; it shares only `@vehiclevo/licensing-shared`.

### Migrations

Append-only `packages/server/migrations/NNN_*.sql`, tracked in `schema_migrations`, applied idempotently on server startup (or via CLI). Never edit an applied migration — add a new numbered file. Schema changes usually ripple: migration → domain type → both memory and Postgres adapters → (sometimes) portal API types in `admin-web/src/api.ts` or `customer-web/src/api.ts`.

## Repo-specific security invariants

- Activation-code plaintext exists only in the generation response and offline request files: only the HMAC hash is persisted; `getLicenseDetail` strips `codeHash` before it reaches the portal (a test asserts this). Never log codes or full tokens.
- Secret comparisons use `timingSafeEqual`; IDs are prefixed UUIDs (non-enumerable).
- `keys/` and `.env` are gitignored — dev keypairs are generated, never committed.
- The threat model (`docs/threat-model.md`) tracks mitigation status per threat; update it when changing security posture, and keep the codebase's "honest limitation" comments (client-side licensing raises cost, cannot prevent) intact.
