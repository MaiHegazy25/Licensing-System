# Vehiclevo Licensing System

A centralized platform to sell, issue, activate, validate, renew, suspend,
revoke and audit licenses for Vehiclevo's commercial software — plus a reusable
client SDK that tools embed **without** access to internal administration.

> **Status:** Stage 3 vertical slice implemented and tested. Stages 2 (design
> docs) delivered under `docs/`. Extended features (offline files, floating,
> portals, KMS, reporting) are designed and phased — see
> `docs/architecture.md` §8. Items not yet built are marked _(planned)_.

## Honest security note

Client-side licensing **raises the cost** of bypassing licensing but **cannot
make software uncrackable**. An attacker in full control of a device can patch
checks. This system targets casual copying, license sharing, and reliable
expiry/revocation enforcement with tamper-evidence — not unbreakable DRM. The
strongest guarantees are server-side (revocation, seat caps, audit); the SDK
enforces signed, time-bounded entitlements and fails **safe**.

## Layout

```
packages/
  shared/     canonical JSON + Ed25519 token sign/verify (used by server AND sdk)
  server/     domain (license state machine) · app services · signing · API · migrations
  sdk/        client SDK: init/activate/validate/hasFeature/offline/rollback
  admin-web/  React + TS admin portal (Vite): products, licenses, audit
docs/         architecture · threat-model · license-lifecycle · ADRs
```

Design principle: `domain` depends on nothing; `application` on `domain`+ports;
`infrastructure` implements ports; the SDK shares only `shared` — never server
internals or private keys.

## Quickstart (local dev)

```bash
npm install
npm test                 # 16 tests: crypto/token, e2e slice, SDK offline/rollback
npm run build            # compile all packages

# generate a DEV signing keypair (gitignored; never commit private keys)
node --loader ts-node/esm packages/server/scripts/keygen.ts key-2026-01 ./keys/local
cp .env.example .env     # then set ACTIVE_SIGNING_KEY_ID + ACTIVATION_CODE_PEPPER
npm start -w @vehiclevo/licensing-server
```

By default the server runs on **in-memory** repositories (zero external deps).
Set `DATABASE_URL` to switch to **Postgres**: the server applies pending
migrations on startup (idempotent, tracked in `schema_migrations`) and uses the
`pg`-backed adapters. Seat checkout is enforced atomically with a
`SELECT … FOR UPDATE` row lock, so concurrent activations can never oversell.

```bash
docker compose up -d db                 # local Postgres
export DATABASE_URL=postgres://licensing:licensing@localhost:5432/licensing
npm run migrate -w @vehiclevo/licensing-server   # or let startup auto-apply
npm start -w @vehiclevo/licensing-server

# Postgres integration tests (skipped unless a DB is provided):
TEST_DATABASE_URL=$DATABASE_URL npm test
```

## What the slice proves (Stage 3)

`admin creates product + license → generates activation code → SDK activates →
SDK verifies the signed token locally → app gates a feature → admin revokes →
SDK detects revocation on next online validation`, plus seat-limit enforcement,
offline operation within the signed window, and clock-rollback detection. All
covered by `packages/**/__tests__`.

## Admin portal

A React + TypeScript SPA (`packages/admin-web`) for license management: list/
create products, list/filter/create licenses, view license detail (devices,
seat usage, activation-code metadata — **never** code plaintext/hash), generate
activation codes, and suspend/resume/renew/revoke — plus an audit log with CSV
export.

```bash
# terminal 1: backend (see Quickstart to set env + keys)
npm start -w @vehiclevo/licensing-server
# terminal 2: portal (dev server proxies /api -> :8080)
npm run dev -w @vehiclevo/licensing-admin-web   # http://localhost:5173
npm run build -w @vehiclevo/licensing-admin-web # production bundle
```

### RBAC — five roles

The five roles from the brief are enforced server-side via a permission matrix
(`domain/rbac.ts`; see ADR-0005). Every admin endpoint requires a specific
permission; the portal fetches `/api/v1/admin/me` and hides controls the role
can't use (the server stays the enforcer). The acting user is recorded in the
audit trail.

| Role | Can |
|---|---|
| `system_admin` | everything, incl. system config |
| `license_admin` | full license lifecycle (create/manage/revoke), products, codes, audit |
| `sales_ops` | create licenses, issue activation codes, read |
| `support` | issue codes (activation reset), read |
| `auditor` | read + audit only (no writes) |

Authentication is selectable behind one `PrincipalResolver` port (`AUTH_MODE`):

- **`apikey`** (default, dev): API keys mapped to roles — `ADMIN_API_KEY`
  (legacy → system_admin) or `ADMIN_API_KEYS` JSON for roled keys. Entered at
  login, held in sessionStorage, sent as a Bearer token, never logged.
- **`oidc`** (production): validates IdP-issued JWT access tokens (Entra ID /
  Keycloak) — RS256 signature checked against the IdP JWKS, `iss`/`aud`/`exp`
  enforced, and the configured role/group claim mapped to our roles
  (`OIDC_*` env). Uses Node's built-in crypto; no JWT library. `alg:none` and
  non-RS256 tokens are rejected.

Either way the **same permission matrix** enforces access; routes are unchanged.
Backend endpoints live under `/api/v1/admin/*` with CORS for the SPA origin
(`ADMIN_WEB_ORIGIN`).

## Customer portal

A separate React SPA (`packages/customer-web`) for end customers — no access to
internal administration. Customers can view their licenses, enabled features,
expiry/maintenance dates and seat usage; view and **deactivate their own
devices** (freeing a seat, enabling transfer); **download a signed license
file**; and **request an activation reset**.

```bash
npm run dev -w @vehiclevo/licensing-customer-web    # http://localhost:5174
npm run build -w @vehiclevo/licensing-customer-web
```

The customer API lives under `/api/v1/customer/*` and is **strictly scoped to
the authenticated customer** — every response is filtered to their `customerId`,
and any attempt to read or act on another customer's license returns `404` (no
existence leak). Auth for the slice is customer access keys (`CUSTOMER_API_KEYS`)
behind a `CustomerPrincipalResolver` port; production swaps in a customer
OIDC/B2C resolver. Isolation is covered by tests (`customer-api.test.ts`).

## SDK integration examples

### Startup
```ts
import { initializeLicensing, FetchHttpClient, FileTokenStore } from "@vehiclevo/licensing-sdk";

const licensing = await initializeLicensing({
  serverUrl: "https://licensing.vehiclevo.example",
  expectedIssuer: "https://licensing.vehiclevo.example",
  expectedAudience: "vehiclevo-products",
  deviceId: deriveDeviceId(),                 // salted/derived — NOT a raw MAC
  publicKeys: [{ kid: "key-2026-01", pem: EMBEDDED_PUBLIC_KEY_PEM }],
  http: new FetchHttpClient("https://licensing.vehiclevo.example"),
  store: new FileTokenStore(appDataPath("license.json")), // wrap OS keychain in prod
});

const status = await licensing.validateLicense();
if (!status.ok) showLicensingScreen(status);  // fails safe: features stay off
```

### Periodic validation
```ts
setInterval(() => { void licensing.validateLicense(); }, 6 * 60 * 60 * 1000);
```

### Floating (concurrent) seats
```ts
const seat = await licensing.checkoutSeat();        // throws SeatUnavailable if full
const hb = setInterval(async () => {
  try { await licensing.heartbeatSeat(); }          // keep the lease alive
  catch { clearInterval(hb); await licensing.checkoutSeat(); } // reclaimed → re-checkout
}, seat.expiresAt ? 60_000 : 60_000);
// on shutdown:
clearInterval(hb);
await licensing.returnSeat();                        // free the seat immediately
```
A crashed client needs no cleanup — its lease expires and the seat is reclaimed
automatically. Checkout is atomic server-side (license row lock), so the
concurrent cap can never be exceeded even under parallel checkout.

### Feature gating (not a single bypassable gate — re-check at the call site)
```ts
function exportPdf() {
  if (!licensing.hasFeature("export_pdf")) {
    throw new Error(licensing.getLicenseStatus().reason ?? "not licensed");
  }
  // ... perform export
}
```

### Activation
```ts
try {
  const snap = await licensing.activate(userEnteredCode);
  console.log("activated:", snap.edition, snap.features);
} catch (e) {
  showError((e as LicensingError).userMessage); // friendly, safe message
}
```

### Self-service trial
```ts
try {
  const snap = await licensing.startTrial("vv-analyzer");  // no code needed
  console.log("trial started:", snap.features);
} catch (e) {
  const err = e as LicensingError;
  if (err.code === LicensingErrorCode.TrialAlreadyUsed) showBuyDialog();
  else if (err.code === LicensingErrorCode.TrialNotAvailable) hideTrialButton();
}
```
Trials are configured per product in the admin portal (enabled, days,
features). The server enforces **one trial per device per product** (DB unique
constraint, race-proof) and issues a **device-bound** token. Repeat calls while
the trial runs resume its remaining days; after it ends they throw
`TrialAlreadyUsed`. Honest limit: the guard keys on the derived device id, which
raises the cost of trial farming but cannot fully prevent it.

### Offline (air-gapped) activation
```ts
// 1) On the air-gapped machine — no network needed:
const request = licensing.generateOfflineRequest(activationCode);
writeFile("request.json", JSON.stringify(request));   // carry to a connected machine / portal

// 2) A connected machine / the portal submits it:
//    POST /api/v1/offline/response  -> downloads response.json (signed, device-bound)

// 3) Back on the air-gapped machine — verified locally, still no network:
const snap = await licensing.importOfflineResponse(JSON.parse(readFile("response.json")));
if (snap.ok) enableApp();
```
The response embeds a signed, **device-bound** license token with a long
`offlineUntil`, so the machine runs offline for the license term. Re-submitting
the same request is idempotent (no extra seat), and a response file copied to a
different device is rejected (`DeviceMismatch`).

### Logout / deactivate & graceful shutdown
```ts
await licensing.deactivate();          // releases the seat server-side
                                       // (proof-of-possession), returns any
                                       // floating seat, then clears local state
// on shutdown just stop the validation timer; the signed cache persists
```

### Offline visibility
```ts
const daysLeft = licensing.getOfflineDaysRemaining();
```

Every dependency (`http`, `store`, `clock`) is injectable, so host-app tests
mock the network and control time deterministically — see
`packages/sdk/src/__tests__/offline.test.ts`.

## Signed token claims

See `packages/shared/src/token.ts` (`LicenseClaims`). Highlights: `schemaVersion`,
`tokenId` (jti), `licenseId`, `customerId`, `organizationId`, `productId`,
`edition`, `enabledFeatures`, `licenseType`, `issuedAt/notBefore/expiresAt`,
`maintenanceExpiresAt`, `maximumSeats`, `deviceBinding`, `offlineUntil`,
`gracePeriodSeconds`, `issuer/audience`, `kid`.

## Security posture (implemented)

- Ed25519 signatures; canonical JSON payload; `kid`-based rotation support.
- Private keys never in client or repo; `local` provider blocked in production;
  **KMS/HSM provider** (Azure Key Vault, EdDSA over REST) signs in the vault so
  private keys never enter the process (`SIGNING_PROVIDER=kms`), with `kid`
  rotation.
- Activation codes: high-entropy, HMAC(pepper) hashed at rest, use-limited,
  constant-time compare.
- Fail-safe SDK; offline window + grace; clock-rollback detection.
- Opaque UUID ids; audit events without secrets; structured logs never carry
  tokens/codes/keys.

See `docs/threat-model.md` for the full threat table and residual risks.
