# Deployment runbook

Deploying the licensing server + portals to production. The reference target is
Azure (Managed HSM holds the Ed25519 signing key — see ADR-0004); any container
host + managed Postgres works with the same steps.

## 0. What gets deployed

| Component | Artifact | Where |
|---|---|---|
| Licensing server | Docker image (`Dockerfile`, built/pushed by CI to GHCR) | container host behind TLS |
| Admin portal | static bundle `packages/admin-web/dist` | static host / CDN |
| Customer portal | static bundle `packages/customer-web/dist` | static host / CDN |
| Database | PostgreSQL 16+, migrations in `packages/server/migrations` | managed Postgres |

The app serves plain HTTP — **TLS terminates at your gateway/ingress**, always.

## 1. Provision

1. **Managed PostgreSQL**: create a `licensing` database + least-privilege app
   user. Enable automated backups + PITR — this database is the licensing truth
   (revocations, seats, trials).
2. **Signing key (key ceremony)**: in Azure Key Vault **Managed HSM** create an
   Ed25519 key; note its name + version. Create a service principal with *sign*
   and *get* key permissions only; store its client secret in your secrets
   manager. Standard Key Vault does not offer Ed25519 — Managed HSM does.
3. **Entra ID app registration** for admin OIDC: define app roles (e.g.
   `Licensing.Admin`, `Licensing.Audit`); note issuer, audience, JWKS URI.
4. **Container host** (Azure Container Apps / App Service) with an ingress that
   terminates TLS and forwards to port 8080.

## 2. Configure (all via secrets manager / host env — never files in the image)

| Variable | Production value |
|---|---|
| `LICENSING_ENV` | `production` — blocks the local signing provider and requires an explicit CORS origin (fail-fast) |
| `LICENSING_HTTP_PORT` | `8080` |
| `DATABASE_URL` | managed Postgres connection string |
| `SIGNING_PROVIDER` / `KMS_PROVIDER` | `kms` / `azure` |
| `AZURE_KEY_VAULT_URL` | Managed HSM endpoint |
| `KMS_KEYS` | `{"key-2026-01":{"name":"licensing-signing","version":"<ver>"}}` |
| `ACTIVE_SIGNING_KEY_ID` | the kid to sign new tokens with |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | the signing service principal |
| `TOKEN_ISSUER` / `TOKEN_AUDIENCE` | real licensing URL / product audience — baked into every token; changing later breaks cached client trust |
| `ACTIVATION_CODE_PEPPER` | ≥16 chars; rotating it invalidates all outstanding activation codes |
| `AUTH_MODE` | `oidc` |
| `OIDC_ISSUER` / `OIDC_AUDIENCE` / `OIDC_JWKS_URI` / `OIDC_ROLE_CLAIM` / `OIDC_ROLE_MAP` | from the Entra registration; e.g. `OIDC_ROLE_MAP={"Licensing.Admin":"license_admin","Licensing.Audit":"auditor"}` |
| `CUSTOMER_API_KEYS` | customer-portal access keys (customer OIDC/B2C resolver not yet built) |
| `ADMIN_WEB_ORIGIN` / `CUSTOMER_WEB_ORIGIN` | exact portal origins (each SPA has its own) — wildcard refused in production |
| `TRUST_PROXY` | **required behind a load balancer** (`true`, a hop count, or CIDRs) — otherwise rate limiting keys on the balancer's IP and all callers share one bucket |
| Tuning | `TOKEN_TTL_SECONDS`, `FLOATING_LEASE_TTL_SECONDS`, `OFFLINE_TOKEN_MAX_DAYS`, `RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW_SECONDS` |

## 3. Migrate, then roll

- **Single instance**: startup auto-applies pending migrations; just deploy.
- **Multiple instances**: apply migrations as a release step *before* rolling:

  ```bash
  DATABASE_URL=... npm run migrate -w @vehiclevo/licensing-server
  # or from the image:
  docker run --rm -e DATABASE_URL=... ghcr.io/<org>/licensing-system/licensing-server:<sha> \
    node packages/server/dist/infrastructure/persistence/migrate.js
  ```

Health probes: liveness `GET /health`, readiness `GET /ready` (also proves the
trusted signing kids loaded from the vault).

## 4. Deploy the portals

Build (`npm run build -w @vehiclevo/licensing-admin-web`, same for
customer-web) and host the `dist/` bundles statically. Either serve them under
the same origin with a path proxy for `/api` (no CORS involved), or on their own
origins with `ADMIN_WEB_ORIGIN` set to the admin portal's origin.

## 5. Distribute the public key to products

Fetch the SPKI PEM from `GET /api/v1/keys` (or export from the vault) and embed
it in each product's SDK config (`publicKeys: [{ kid, pem }]`). Ship current +
next kid so rotation is non-breaking.

## 6. Post-deploy smoke test

Run the vertical slice against the live system: create product → create license
→ generate activation code → activate from an SDK client → `hasFeature()` true →
revoke → next validate returns `revoked`. Confirm the audit log recorded each
step under the real acting principal.

## 7. CI/CD

`.github/workflows/ci.yml` runs on every PR/push: typecheck, both SPA builds,
the full test suite against a real Postgres service container, and an advisory
`npm audit`. On `main` it additionally builds the server image, pushes it to
GHCR (`:latest` + `:<sha>`), generates an SPDX SBOM artifact, and runs a
container vulnerability scan (advisory).

**Deploy job** is intentionally not wired — it needs your cloud credentials.
For Azure Container Apps, append:

```yaml
  deploy:
    needs: image
    runs-on: ubuntu-latest
    environment: production   # require manual approval in repo settings
    steps:
      - uses: azure/login@v2
        with: { creds: "${{ secrets.AZURE_CREDENTIALS }}" }
      - uses: azure/container-apps-deploy-action@v2
        with:
          containerAppName: licensing-server
          resourceGroup: licensing-rg
          imageToDeploy: ghcr.io/${{ github.repository }}/licensing-server:${{ github.sha }}
```

## 8. Key rotation (condensed from ADR-0004)

1. Create the new key in the HSM; add its kid to `KMS_KEYS`.
2. Ship the new public key to clients (SDK trust stores / `/api/v1/keys`).
3. Flip `ACTIVE_SIGNING_KEY_ID` to the new kid; redeploy.
4. Retire the old kid after all tokens signed by it have expired.

**Compromise**: remove the kid from `KMS_KEYS` immediately, rotate, force
re-issue; treat all tokens under the compromised kid as suspect.

## Known gaps (plan for these)

- No metrics/tracing/dashboards yet — logs are structured JSON on stdout; point
  your aggregator at the containers.
- The rate limiter is per-instance; front replicas with a gateway limiter.
- Customer-portal auth is API keys; the customer OIDC/B2C resolver is the
  planned production replacement behind the existing port.
