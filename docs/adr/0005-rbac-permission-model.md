# ADR-0005: RBAC with a permission matrix behind an auth port

- Status: Accepted
- Date: 2026-07-22

## Context
The brief defines five admin roles (system administrator, license
administrator, sales/operations, support, auditor/read-only). The slice
previously had a single admin API key with all-or-nothing access.

## Decision
- Define **granular permissions** (`product:read/write`, `license:read/create/
  manage/revoke`, `activation:issue`, `audit:read`, `system:admin`) and a
  **role → permission matrix** (`domain/rbac.ts`, the authoritative source).
- Endpoints require a **permission**, not a role — policy stays explicit and
  roles can be retuned without touching routes.
- Authentication is a **port** (`PrincipalResolver`) that maps a bearer token to
  a `Principal {subject, role}`. The slice adapter resolves API keys (legacy
  `ADMIN_API_KEY` → system_admin; `ADMIN_API_KEYS` JSON → roled keys), compared
  in constant time. **Production** swaps in an OIDC-token resolver behind the
  same port — routes and matrix unchanged.
- The acting `principal.subject` is threaded into the **audit trail** (no more
  generic "admin").
- The portal fetches `/admin/me` and mirrors the matrix to **hide controls**;
  the server remains the sole enforcer (defense in depth, not client trust).

## Role → permission summary
| Permission | sys_admin | lic_admin | sales_ops | support | auditor |
|---|:-:|:-:|:-:|:-:|:-:|
| product:read | ✅ | ✅ | ✅ | ✅ | ✅ |
| product:write | ✅ | ✅ | | | |
| license:read | ✅ | ✅ | ✅ | ✅ | ✅ |
| license:create | ✅ | ✅ | ✅ | | |
| license:manage (suspend/resume/renew) | ✅ | ✅ | | | |
| license:revoke | ✅ | ✅ | | | |
| activation:issue (codes / reset) | ✅ | ✅ | ✅ | ✅ | |
| audit:read | ✅ | ✅ | | | ✅ |
| system:admin | ✅ | | | | |

## Consequences
- (+) Least-privilege access; auditor is truly read-only; support can run
  activation resets without license-management power.
- (+) OIDC migration is localized to one adapter.
- (−) API keys in env are dev-only secrets; documented as such and blocked-in-
  spirit by the production OIDC path.
