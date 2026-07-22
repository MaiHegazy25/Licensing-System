/**
 * API-key PrincipalResolver (dev / vertical slice).
 *
 * Maps bearer tokens to principals. Keys come from env:
 *   - ADMIN_API_KEY            legacy single key -> subject "admin", system_admin
 *   - ADMIN_API_KEYS (JSON)    [{ "subject": "...", "role": "...", "key": "..." }]
 *
 * Keys are compared in constant time. This is DEV plumbing; production swaps in
 * an OIDC-token resolver behind the same PrincipalResolver port. Keys are
 * secrets — they live only in a secrets manager, never in source.
 */
import { timingSafeEqual } from "node:crypto";
import { isRole, type Role } from "../../domain/rbac.js";
import type { Principal, PrincipalResolver } from "../../application/auth.js";

interface Entry {
  key: string;
  principal: Principal;
}

export class ApiKeyPrincipalResolver implements PrincipalResolver {
  private constructor(private readonly entries: Entry[]) {}

  static fromEnv(env: NodeJS.ProcessEnv = process.env): ApiKeyPrincipalResolver {
    const entries: Entry[] = [];

    const legacy = env.ADMIN_API_KEY;
    if (legacy && legacy.length > 0) {
      entries.push({ key: legacy, principal: { subject: "admin", role: "system_admin" } });
    }

    const json = env.ADMIN_API_KEYS;
    if (json && json.trim().length > 0) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(json);
      } catch {
        throw new Error("ADMIN_API_KEYS is not valid JSON");
      }
      if (!Array.isArray(parsed)) throw new Error("ADMIN_API_KEYS must be a JSON array");
      for (const raw of parsed) {
        const e = raw as { subject?: unknown; role?: unknown; key?: unknown };
        if (typeof e.subject !== "string" || typeof e.key !== "string" || typeof e.role !== "string") {
          throw new Error("ADMIN_API_KEYS entries need string subject, role, key");
        }
        if (!isRole(e.role)) throw new Error(`ADMIN_API_KEYS: unknown role '${e.role}'`);
        entries.push({ key: e.key, principal: { subject: e.subject, role: e.role as Role } });
      }
    }
    return new ApiKeyPrincipalResolver(entries);
  }

  isConfigured(): boolean {
    return this.entries.length > 0;
  }

  async resolve(bearerToken: string | null): Promise<Principal | null> {
    if (!bearerToken) return null;
    const presented = Buffer.from(bearerToken);
    for (const entry of this.entries) {
      const stored = Buffer.from(entry.key);
      if (stored.length === presented.length && timingSafeEqual(stored, presented)) {
        return entry.principal;
      }
    }
    return null;
  }
}
