/**
 * Customer-portal API-key resolver (dev / slice). Maps a bearer token to a
 * CustomerPrincipal (customerId scope). Keys come from env:
 *   CUSTOMER_API_KEYS (JSON): [{ "customerId": "...", "subject": "...", "key": "..." }]
 *
 * Keys are compared in constant time and are secrets (secrets manager in real
 * environments). Production replaces this with a customer OIDC / B2C resolver
 * behind the same CustomerPrincipalResolver port; the `customerId` then comes
 * from a verified token claim.
 */
import { timingSafeEqual } from "node:crypto";
import type { CustomerPrincipal, CustomerPrincipalResolver } from "../../application/auth.js";

interface Entry {
  key: string;
  principal: CustomerPrincipal;
}

export class CustomerApiKeyResolver implements CustomerPrincipalResolver {
  private constructor(private readonly entries: Entry[]) {}

  static fromEnv(env: NodeJS.ProcessEnv = process.env): CustomerApiKeyResolver {
    const entries: Entry[] = [];
    const json = env.CUSTOMER_API_KEYS;
    if (json && json.trim().length > 0) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(json);
      } catch {
        throw new Error("CUSTOMER_API_KEYS is not valid JSON");
      }
      if (!Array.isArray(parsed)) throw new Error("CUSTOMER_API_KEYS must be a JSON array");
      for (const raw of parsed) {
        const e = raw as { customerId?: unknown; subject?: unknown; key?: unknown };
        if (typeof e.customerId !== "string" || typeof e.key !== "string") {
          throw new Error("CUSTOMER_API_KEYS entries need string customerId and key");
        }
        entries.push({
          key: e.key,
          principal: {
            customerId: e.customerId,
            subject: typeof e.subject === "string" ? e.subject : e.customerId,
          },
        });
      }
    }
    return new CustomerApiKeyResolver(entries);
  }

  isConfigured(): boolean {
    return this.entries.length > 0;
  }

  async resolve(bearerToken: string | null): Promise<CustomerPrincipal | null> {
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
