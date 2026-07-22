/**
 * OIDC resolver: RS256 JWT verification against a JWKS + role-claim mapping.
 * Tokens are minted locally with an RSA key (standing in for the IdP), so no
 * network / real IdP is needed.
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  generateKeyPairSync,
  sign as nodeSign,
  createPublicKey,
  type KeyObject,
} from "node:crypto";
import {
  OidcPrincipalResolver,
  RemoteJwksProvider,
  type JwksKeyProvider,
  type OidcConfig,
} from "@vehiclevo/licensing-server";

const KID = "idp-key-1";
const ISSUER = "https://login.example.com/tenant";
const AUDIENCE = "api://licensing";
const NOW = 1_700_000_000;

let privateKey: KeyObject;
let publicKey: KeyObject;

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function signJwt(claims: Record<string, unknown>, opts: { kid?: string; alg?: string } = {}): string {
  const header = { alg: opts.alg ?? "RS256", kid: opts.kid ?? KID, typ: "JWT" };
  const data = `${b64url(header)}.${b64url(claims)}`;
  const sig = nodeSign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url");
  return `${data}.${sig}`;
}

function baseClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: "user-123",
    iss: ISSUER,
    aud: AUDIENCE,
    exp: NOW + 3600,
    nbf: NOW - 10,
    roles: ["Licensing.Admin"],
    ...over,
  };
}

const cfg: OidcConfig = {
  issuer: ISSUER,
  audience: AUDIENCE,
  roleClaim: "roles",
  roleMap: {
    "Licensing.SystemAdmin": "system_admin",
    "Licensing.Admin": "license_admin",
    "Licensing.Sales": "sales_ops",
    "Licensing.Support": "support",
    "Licensing.Audit": "auditor",
  },
  now: () => NOW,
};

const localJwks: JwksKeyProvider = {
  async getKey(kid) {
    return kid === KID ? publicKey : null;
  },
};

beforeAll(() => {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  privateKey = pair.privateKey;
  publicKey = pair.publicKey;
});

describe("OidcPrincipalResolver", () => {
  const resolver = new OidcPrincipalResolver(localJwks, cfg);

  it("accepts a valid token and maps the role claim", async () => {
    const p = await resolver.resolve(signJwt(baseClaims()));
    expect(p).toEqual({ subject: "user-123", role: "license_admin" });
  });

  it("picks the most-privileged role when several are present", async () => {
    const token = signJwt(baseClaims({ roles: ["Licensing.Audit", "Licensing.SystemAdmin"] }));
    expect((await resolver.resolve(token))?.role).toBe("system_admin");
  });

  it("rejects an expired token", async () => {
    expect(await resolver.resolve(signJwt(baseClaims({ exp: NOW - 3600 })))).toBeNull();
  });

  it("rejects a not-yet-valid token", async () => {
    expect(await resolver.resolve(signJwt(baseClaims({ nbf: NOW + 3600 })))).toBeNull();
  });

  it("rejects wrong issuer and wrong audience", async () => {
    expect(await resolver.resolve(signJwt(baseClaims({ iss: "https://evil" })))).toBeNull();
    expect(await resolver.resolve(signJwt(baseClaims({ aud: "api://other" })))).toBeNull();
  });

  it("rejects a tampered payload (signature mismatch)", async () => {
    const token = signJwt(baseClaims());
    const [h, p, s] = token.split(".") as [string, string, string];
    const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    claims.roles = ["Licensing.SystemAdmin"]; // privilege escalation attempt
    const forged = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;
    expect(await resolver.resolve(forged)).toBeNull();
  });

  it("rejects alg=none and unexpected algorithms", async () => {
    expect(await resolver.resolve(signJwt(baseClaims(), { alg: "none" }))).toBeNull();
    expect(await resolver.resolve(signJwt(baseClaims(), { alg: "HS256" }))).toBeNull();
  });

  it("rejects an unknown signing key id", async () => {
    expect(await resolver.resolve(signJwt(baseClaims(), { kid: "unknown" }))).toBeNull();
  });

  it("authenticates but denies when no role maps (returns null)", async () => {
    expect(await resolver.resolve(signJwt(baseClaims({ roles: ["Some.Other.Group"] })))).toBeNull();
    expect(await resolver.resolve(signJwt(baseClaims({ roles: [] })))).toBeNull();
  });

  it("rejects malformed tokens", async () => {
    expect(await resolver.resolve("not.a.jwt")).toBeNull();
    expect(await resolver.resolve(null)).toBeNull();
  });
});

describe("RemoteJwksProvider", () => {
  it("fetches, caches, and converts JWKs; unknown kid -> null", async () => {
    const jwk = { ...(publicKey.export({ format: "jwk" }) as object), kid: KID, use: "sig", alg: "RS256" };
    let fetches = 0;
    const fetchImpl = (async () => {
      fetches++;
      return new Response(JSON.stringify({ keys: [jwk] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const provider = new RemoteJwksProvider("https://idp/jwks", 300, () => NOW, fetchImpl);
    const key = await provider.getKey(KID);
    expect(key).toBeTruthy();
    // Second lookup is served from cache (no extra fetch).
    await provider.getKey(KID);
    expect(fetches).toBe(1);
    // A token signed by our key verifies against the fetched public key.
    const resolver = new OidcPrincipalResolver(provider, cfg);
    expect((await resolver.resolve(signJwt(baseClaims())))?.role).toBe("license_admin");
    expect(await provider.getKey("nope")).toBeNull();
  });
});
