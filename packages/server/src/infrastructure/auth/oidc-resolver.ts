/**
 * OIDC PrincipalResolver (production).
 *
 * Validates a JWT access token issued by an IdP (Microsoft Entra ID / Keycloak):
 *   1. RS256 signature verified against the IdP's JWKS (public keys by kid),
 *   2. issuer / audience / expiry / not-before checked,
 *   3. the configured role/group claim mapped to one of our five Roles.
 *
 * Uses only Node's built-in crypto (JWK -> KeyObject via `format: "jwk"`), so no
 * third-party JWT library is required. The private keys stay at the IdP; we only
 * ever consume public keys. Behind the same PrincipalResolver port as the
 * API-key resolver, so routes and the permission matrix are unchanged.
 */
import { createPublicKey, verify as nodeVerify, type KeyObject } from "node:crypto";
import { ROLES, isRole, type Role } from "../../domain/rbac.js";
import type { Principal, PrincipalResolver } from "../../application/auth.js";

/** Resolves a signing key (public) by its `kid`. */
export interface JwksKeyProvider {
  getKey(kid: string): Promise<KeyObject | null>;
}

export interface OidcConfig {
  issuer: string;
  audience: string;
  /** Claim carrying the caller's roles/groups (e.g. "roles" or "groups"). */
  roleClaim: string;
  /** Maps an IdP role/group value to one of our Roles. */
  roleMap: Record<string, Role>;
  /** Epoch-seconds clock (injectable for deterministic tests). */
  now?: () => number;
  /** Small leeway (s) for clock skew on exp/nbf. Default 60. */
  clockToleranceSeconds?: number;
}

interface JwtHeader {
  alg: string;
  kid?: string;
}
interface JwtClaims {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  [claim: string]: unknown;
}

function decodeSegment(seg: string): unknown {
  return JSON.parse(Buffer.from(seg, "base64url").toString("utf8"));
}

export class OidcPrincipalResolver implements PrincipalResolver {
  private readonly now: () => number;
  private readonly tolerance: number;

  constructor(
    private readonly keys: JwksKeyProvider,
    private readonly cfg: OidcConfig,
  ) {
    this.now = cfg.now ?? (() => Math.floor(Date.now() / 1000));
    this.tolerance = cfg.clockToleranceSeconds ?? 60;
  }

  isConfigured(): boolean {
    return true;
  }

  async resolve(bearerToken: string | null): Promise<Principal | null> {
    if (!bearerToken) return null;
    const parts = bearerToken.split(".");
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

    let header: JwtHeader;
    let claims: JwtClaims;
    try {
      header = decodeSegment(headerB64) as JwtHeader;
      claims = decodeSegment(payloadB64) as JwtClaims;
    } catch {
      return null;
    }

    // Only RS256 is accepted — never trust `alg: none` or an unexpected alg.
    if (header.alg !== "RS256" || !header.kid) return null;

    const key = await this.keys.getKey(header.kid);
    if (!key) return null;

    const data = Buffer.from(`${headerB64}.${payloadB64}`);
    const signature = Buffer.from(sigB64, "base64url");
    let signatureValid = false;
    try {
      signatureValid = nodeVerify("RSA-SHA256", data, key, signature);
    } catch {
      return null;
    }
    if (!signatureValid) return null;

    // Standard claim checks.
    if (claims.iss !== this.cfg.issuer) return null;
    const aud = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
    if (!aud.includes(this.cfg.audience)) return null;

    const now = this.now();
    if (typeof claims.exp === "number" && now > claims.exp + this.tolerance) return null;
    if (typeof claims.nbf === "number" && now + this.tolerance < claims.nbf) return null;
    if (!claims.sub) return null;

    const role = this.mapRole(claims[this.cfg.roleClaim]);
    if (!role) return null; // authenticated but no recognized role -> deny

    return { subject: claims.sub, role };
  }

  /** Map the role/group claim (string or array) to our highest-privilege Role. */
  private mapRole(claimValue: unknown): Role | null {
    const values = Array.isArray(claimValue)
      ? claimValue
      : typeof claimValue === "string"
        ? [claimValue]
        : [];
    const mapped: Role[] = [];
    for (const v of values) {
      if (typeof v !== "string") continue;
      const r = this.cfg.roleMap[v];
      if (r && isRole(r)) mapped.push(r);
    }
    if (mapped.length === 0) return null;
    // Most privileged wins (ROLES is ordered from most to least privileged).
    for (const role of ROLES) if (mapped.includes(role)) return role;
    return null;
  }
}

/**
 * JWKS provider that fetches and caches the IdP's public keys. Refreshes on a
 * cache miss (key rotation) with a minimum refresh interval to avoid hammering
 * the IdP on bad `kid`s.
 */
export class RemoteJwksProvider implements JwksKeyProvider {
  private cache = new Map<string, KeyObject>();
  private lastFetch = 0;

  constructor(
    private readonly jwksUri: string,
    private readonly minRefreshSeconds = 300,
    private readonly now: () => number = () => Math.floor(Date.now() / 1000),
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async getKey(kid: string): Promise<KeyObject | null> {
    if (this.cache.has(kid)) return this.cache.get(kid)!;
    if (this.now() - this.lastFetch >= this.minRefreshSeconds) {
      await this.refresh();
    }
    return this.cache.get(kid) ?? null;
  }

  private async refresh(): Promise<void> {
    this.lastFetch = this.now();
    const res = await this.fetchImpl(this.jwksUri);
    if (!res.ok) return;
    const body = (await res.json()) as { keys?: Array<Record<string, unknown>> };
    const next = new Map<string, KeyObject>();
    for (const jwk of body.keys ?? []) {
      const kid = jwk.kid;
      if (typeof kid !== "string") continue;
      try {
        next.set(kid, createPublicKey({ key: jwk as never, format: "jwk" }));
      } catch {
        /* skip unusable key */
      }
    }
    this.cache = next;
  }
}
