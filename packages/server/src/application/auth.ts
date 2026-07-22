/**
 * Authentication port. Resolves a presented credential (bearer token) to a
 * Principal, or null if unknown. The API-key resolver is the dev/slice adapter;
 * a production adapter validates an OIDC access token and maps IdP roles/groups
 * to our Role — same port, no route changes.
 */
import type { Role } from "../domain/rbac.js";

export interface Principal {
  subject: string;
  role: Role;
}

export interface PrincipalResolver {
  /**
   * Returns the Principal for a bearer token, or null if it is not recognized.
   * Async because production resolvers (OIDC) verify a JWT against remote JWKS.
   */
  resolve(bearerToken: string | null): Promise<Principal | null>;
  /** True when the resolver is configured (else auth is unconfigured). */
  isConfigured(): boolean;
}
