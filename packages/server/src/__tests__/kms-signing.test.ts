/**
 * KMS signing provider. A simulated Azure Key Vault (backed by a real Ed25519
 * keypair) answers the REST sign/get-key calls, so we exercise the adapter's
 * request/response handling without a real vault. Proves: tokens signed via the
 * KMS verify against the vault's PUBLIC key, the request shape is correct, key
 * rotation works, and the provider only ever holds public keys.
 */
import { describe, it, expect } from "vitest";
import {
  generateEd25519KeyPair,
  privateKeyFromPem,
  publicKeyFromPem,
  signEd25519,
  signLicenseToken,
  verifyLicenseToken,
  type LicenseClaims,
  type PublicKeyStore,
} from "@vehiclevo/licensing-shared";
import type { KeyObject } from "node:crypto";
import {
  AzureKeyVaultSignerClient,
  KmsSigningKeyProvider,
  azureClientCredentialToken,
} from "@vehiclevo/licensing-server";

const ISSUER = "https://licensing.test";
const AUDIENCE = "vehiclevo-products";

interface VaultKey {
  priv: KeyObject;
  pub: KeyObject;
}

/** A fake Key Vault: signs with the real private key, serves the public JWK. */
function fakeVault(keysByName: Map<string, VaultKey>) {
  const calls: Array<{ url: string; method: string; body?: unknown }> = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean); // keys / {name} / {version} [/ sign]
    const name = parts[1]!;
    const entry = keysByName.get(name);
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(init.body as string) : undefined;
    calls.push({ url, method, body });
    if (!entry) return new Response("not found", { status: 404 });

    if (parts[3] === "sign" && method === "POST") {
      const msg = Buffer.from(body.value as string, "base64url");
      const sig = signEd25519(new Uint8Array(msg), entry.priv);
      return json({ kid: `${name}/${parts[2]}`, value: Buffer.from(sig).toString("base64url") });
    }
    if (method === "GET") {
      const jwk = entry.pub.export({ format: "jwk" }) as { x: string };
      return json({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x } });
    }
    return new Response("bad", { status: 400 });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

function json(obj: unknown): Response {
  return new Response(JSON.stringify(obj), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function makeVaultKey(): VaultKey {
  const kp = generateEd25519KeyPair();
  return { priv: privateKeyFromPem(kp.privateKeyPem), pub: publicKeyFromPem(kp.publicKeyPem) };
}

function claims(): LicenseClaims {
  return {
    schemaVersion: 1, tokenId: "tok_1", licenseId: "lic_1", customerId: "c1",
    organizationId: null, productId: "p1", edition: "pro", enabledFeatures: ["f1"],
    licenseType: "subscription", issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    maintenanceExpiresAt: null, maximumSeats: 5, deviceBinding: null, offlineUntil: null,
    gracePeriodSeconds: 0, issuer: ISSUER, audience: AUDIENCE,
  };
}

const verifyOpts = { expectedAudience: AUDIENCE, expectedIssuer: ISSUER, clock: { now: () => 1500 } };

describe("KMS signing provider (Azure Key Vault)", () => {
  it("signs via the vault and the token verifies with the vault's public key", async () => {
    const key = makeVaultKey();
    const { fetchImpl, calls } = fakeVault(new Map([["licensing-signing", key]]));
    const client = new AzureKeyVaultSignerClient({
      vaultUrl: "https://vault.example.net",
      keys: { "key-2026-01": { name: "licensing-signing", version: "v1" } },
      getAccessToken: async () => "test-token",
      fetchImpl,
    });
    const provider = await KmsSigningKeyProvider.create(client, "key-2026-01");

    const token = await signLicenseToken(claims(), provider.activeSigner());
    const result = verifyLicenseToken(token, provider.publicKeyStore(), verifyOpts);
    expect(result.status).toBe("valid");

    // The signature really went through the vault's sign endpoint with EdDSA.
    const signCall = calls.find((c) => c.url.includes("/sign"));
    expect(signCall).toBeTruthy();
    expect((signCall!.body as { alg: string }).alg).toBe("EdDSA");
    expect(signCall!.method).toBe("POST");
  });

  it("rejects a tampered token signed by the KMS key", async () => {
    const key = makeVaultKey();
    const { fetchImpl } = fakeVault(new Map([["k", key]]));
    const client = new AzureKeyVaultSignerClient({
      vaultUrl: "https://v", keys: { kid1: { name: "k", version: "v1" } },
      getAccessToken: async () => "t", fetchImpl,
    });
    const provider = await KmsSigningKeyProvider.create(client, "kid1");
    const token = await signLicenseToken(claims(), provider.activeSigner());
    const [h, p, s] = token.split(".") as [string, string, string];
    const c = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    c.enabledFeatures.push("premium");
    const forged = `${h}.${Buffer.from(JSON.stringify(c)).toString("base64url")}.${s}`;
    expect(verifyLicenseToken(forged, provider.publicKeyStore(), verifyOpts).status).toBe("bad_signature");
  });

  it("supports key rotation: multiple trusted kids, active is signable, old still verifies", async () => {
    const k1 = makeVaultKey();
    const k2 = makeVaultKey();
    const { fetchImpl } = fakeVault(new Map([["old", k1], ["new", k2]]));
    const keys = {
      "key-2025": { name: "old", version: "v1" },
      "key-2026": { name: "new", version: "v1" },
    };
    const client = new AzureKeyVaultSignerClient({
      vaultUrl: "https://v", keys, getAccessToken: async () => "t", fetchImpl,
    });
    // Active = new key. Both public keys are in the trust store.
    const provider = await KmsSigningKeyProvider.create(client, "key-2026");
    expect(provider.trustedKeyIds()[0]).toBe("key-2026");

    const store: PublicKeyStore = provider.publicKeyStore();
    // A token signed under the active (new) key verifies.
    const tNew = await signLicenseToken(claims(), provider.activeSigner());
    expect(verifyLicenseToken(tNew, store, verifyOpts).status).toBe("valid");

    // A token that had been signed under the OLD kid still verifies via the store.
    const oldClient = new AzureKeyVaultSignerClient({
      vaultUrl: "https://v", keys, getAccessToken: async () => "t", fetchImpl,
    });
    const oldProvider = await KmsSigningKeyProvider.create(oldClient, "key-2025");
    const tOld = await signLicenseToken(claims(), oldProvider.activeSigner());
    expect(verifyLicenseToken(tOld, store, verifyOpts).status).toBe("valid");
  });

  it("fails fast when the active kid is not a trusted KMS key", async () => {
    const { fetchImpl } = fakeVault(new Map([["k", makeVaultKey()]]));
    const client = new AzureKeyVaultSignerClient({
      vaultUrl: "https://v", keys: { kid1: { name: "k", version: "v1" } },
      getAccessToken: async () => "t", fetchImpl,
    });
    await expect(KmsSigningKeyProvider.create(client, "does-not-exist")).rejects.toThrow(/not among/);
  });
});

describe("azureClientCredentialToken", () => {
  it("fetches and caches the AAD token until near expiry", async () => {
    let fetches = 0;
    let clock = 1000;
    const fetchImpl = (async () => {
      fetches++;
      return json({ access_token: `tok-${fetches}`, expires_in: 3600 });
    }) as unknown as typeof fetch;
    const getToken = azureClientCredentialToken({
      tenantId: "t", clientId: "c", clientSecret: "s", fetchImpl, now: () => clock,
    });
    expect(await getToken()).toBe("tok-1");
    expect(await getToken()).toBe("tok-1"); // cached
    expect(fetches).toBe(1);
    clock += 3600; // past expiry
    expect(await getToken()).toBe("tok-2");
    expect(fetches).toBe(2);
  });
});
