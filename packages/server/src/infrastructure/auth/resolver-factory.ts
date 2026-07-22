/**
 * Chooses the PrincipalResolver from environment:
 *   - AUTH_MODE=oidc  -> OIDC resolver (validates IdP JWTs; production)
 *   - otherwise       -> API-key resolver (dev / vertical slice)
 *
 * OIDC env:
 *   OIDC_ISSUER, OIDC_AUDIENCE, OIDC_JWKS_URI,
 *   OIDC_ROLE_CLAIM   (default "roles"),
 *   OIDC_ROLE_MAP     JSON object mapping IdP role/group -> our Role,
 *                     e.g. {"Licensing.Admin":"license_admin","Licensing.Audit":"auditor"}
 */
import type { PrincipalResolver } from "../../application/auth.js";
import { ApiKeyPrincipalResolver } from "./api-key-resolver.js";
import {
  OidcPrincipalResolver,
  RemoteJwksProvider,
  type OidcConfig,
} from "./oidc-resolver.js";
import { isRole, type Role } from "../../domain/rbac.js";

function req(env: NodeJS.ProcessEnv, key: string): string {
  const v = env[key];
  if (!v) throw new Error(`missing required config: ${key}`);
  return v;
}

function parseRoleMap(json: string): Record<string, Role> {
  const parsed = JSON.parse(json) as Record<string, string>;
  const out: Record<string, Role> = {};
  for (const [k, v] of Object.entries(parsed)) {
    if (!isRole(v)) throw new Error(`OIDC_ROLE_MAP maps '${k}' to unknown role '${v}'`);
    out[k] = v;
  }
  return out;
}

export function buildPrincipalResolver(
  env: NodeJS.ProcessEnv = process.env,
): PrincipalResolver {
  if ((env.AUTH_MODE ?? "").toLowerCase() === "oidc") {
    const cfg: OidcConfig = {
      issuer: req(env, "OIDC_ISSUER"),
      audience: req(env, "OIDC_AUDIENCE"),
      roleClaim: env.OIDC_ROLE_CLAIM ?? "roles",
      roleMap: parseRoleMap(req(env, "OIDC_ROLE_MAP")),
    };
    const jwks = new RemoteJwksProvider(req(env, "OIDC_JWKS_URI"));
    return new OidcPrincipalResolver(jwks, cfg);
  }
  return ApiKeyPrincipalResolver.fromEnv(env);
}
