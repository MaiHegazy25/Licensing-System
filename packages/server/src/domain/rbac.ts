/**
 * Role-based access control model.
 *
 * Five roles from the brief, mapped to granular permissions. Endpoints require
 * a permission (not a role) so the policy is explicit and roles can be retuned
 * without touching route code. This is the authoritative server-side matrix;
 * the portal mirrors it only to hide controls (never as the enforcement point).
 */

export const ROLES = [
  "system_admin", // System administrator — full control incl. system config
  "license_admin", // License administrator — full license lifecycle
  "sales_ops", // Sales/operations — create licenses, issue codes
  "support", // Support — read + activation reset (secure support workflows)
  "auditor", // Auditor/read-only — read + audit, no writes
] as const;

export type Role = (typeof ROLES)[number];

export const PERMISSIONS = [
  "product:read",
  "product:write",
  "license:read",
  "license:create",
  "license:manage", // suspend / resume / renew
  "license:revoke", // destructive, terminal
  "activation:issue", // generate activation codes / reset activations
  "audit:read",
  "system:admin", // system-level configuration
] as const;

export type Permission = (typeof PERMISSIONS)[number];

const ALL: Permission[] = [...PERMISSIONS];

export const ROLE_PERMISSIONS: Record<Role, ReadonlySet<Permission>> = {
  system_admin: new Set(ALL),
  license_admin: new Set<Permission>([
    "product:read",
    "product:write",
    "license:read",
    "license:create",
    "license:manage",
    "license:revoke",
    "activation:issue",
    "audit:read",
  ]),
  sales_ops: new Set<Permission>([
    "product:read",
    "license:read",
    "license:create",
    "activation:issue",
  ]),
  support: new Set<Permission>([
    "product:read",
    "license:read",
    "activation:issue",
  ]),
  auditor: new Set<Permission>([
    "product:read",
    "license:read",
    "audit:read",
  ]),
};

export function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

export function roleHasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].has(permission);
}

export function permissionsForRole(role: Role): Permission[] {
  return [...ROLE_PERMISSIONS[role]];
}
