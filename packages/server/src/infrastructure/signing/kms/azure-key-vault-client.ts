/**
 * Azure Key Vault (and Managed HSM) signer client via the REST API — no Azure
 * SDK dependency. Uses EdDSA/Ed25519, so the token format is unchanged.
 *
 *  - sign:  POST {vault}/keys/{name}/{version}/sign?api-version=7.4
 *           body { alg: "EdDSA", value: base64url(message) }  -> { value: base64url(sig) }
 *  - key:   GET  {vault}/keys/{name}/{version}?api-version=7.4
 *           -> { key: { kty:"OKP", crv:"Ed25519", x: base64url } }  (public only)
 *
 * Auth is a bearer token for the Key Vault resource; obtained via a pluggable
 * TokenProvider (client-credentials in production, injectable in tests). The
 * private key material stays in the vault/HSM and is never exported.
 */
import { createPublicKey, type KeyObject } from "node:crypto";
import type { KmsSignerClient } from "./kms-signer-client.js";

export type TokenProvider = () => Promise<string>;
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Maps our stable `kid` to a specific Key Vault key name + version. */
export interface AzureKeyRef {
  name: string;
  version: string;
}

export interface AzureKeyVaultConfig {
  /** e.g. https://my-vault.vault.azure.net  (or Managed HSM endpoint). */
  vaultUrl: string;
  /** kid -> vault key coordinates. */
  keys: Record<string, AzureKeyRef>;
  getAccessToken: TokenProvider;
  apiVersion?: string;
  fetchImpl?: FetchLike;
}

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

export class AzureKeyVaultSignerClient implements KmsSignerClient {
  private readonly apiVersion: string;
  private readonly fetchImpl: FetchLike;

  constructor(private readonly cfg: AzureKeyVaultConfig) {
    this.apiVersion = cfg.apiVersion ?? "7.4";
    this.fetchImpl = cfg.fetchImpl ?? ((i, init) => fetch(i, init));
  }

  trustedKeyIds(): string[] {
    return Object.keys(this.cfg.keys);
  }

  private ref(kid: string): AzureKeyRef {
    const ref = this.cfg.keys[kid];
    if (!ref) throw new Error(`no Key Vault key mapped for kid '${kid}'`);
    return ref;
  }

  private async authHeaders(): Promise<Record<string, string>> {
    const token = await this.cfg.getAccessToken();
    return { authorization: `Bearer ${token}`, "content-type": "application/json" };
  }

  async sign(kid: string, data: Uint8Array): Promise<Uint8Array> {
    const { name, version } = this.ref(kid);
    const url = `${this.cfg.vaultUrl}/keys/${name}/${version}/sign?api-version=${this.apiVersion}`;
    const res = await this.fetchImpl(url, {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify({ alg: "EdDSA", value: b64url(data) }),
    });
    if (!res.ok) {
      throw new Error(`Key Vault sign failed for kid '${kid}': HTTP ${res.status}`);
    }
    const body = (await res.json()) as { value?: string };
    if (!body.value) throw new Error("Key Vault sign returned no value");
    return new Uint8Array(Buffer.from(body.value, "base64url"));
  }

  async getPublicKey(kid: string): Promise<KeyObject> {
    const { name, version } = this.ref(kid);
    const url = `${this.cfg.vaultUrl}/keys/${name}/${version}?api-version=${this.apiVersion}`;
    const res = await this.fetchImpl(url, { method: "GET", headers: await this.authHeaders() });
    if (!res.ok) {
      throw new Error(`Key Vault get-key failed for kid '${kid}': HTTP ${res.status}`);
    }
    const body = (await res.json()) as { key?: { kty?: string; crv?: string; x?: string } };
    const jwk = body.key;
    if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x) {
      throw new Error(`Key Vault key '${kid}' is not an Ed25519 (OKP) public key`);
    }
    // Import the OKP JWK as a public KeyObject (Node supports Ed25519 JWK).
    return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x } as never, format: "jwk" });
  }
}

/**
 * Azure AD client-credentials token provider (production). Fetches + caches a
 * bearer token for the Key Vault resource. Secrets come from a secrets manager
 * via env — never hard-coded.
 */
export function azureClientCredentialToken(opts: {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  fetchImpl?: FetchLike;
  now?: () => number;
}): TokenProvider {
  const fetchImpl = opts.fetchImpl ?? ((i, init) => fetch(i, init));
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const scope = opts.scope ?? "https://vault.azure.net/.default";
  let cached: { token: string; exp: number } | null = null;

  return async () => {
    if (cached && now() < cached.exp - 60) return cached.token;
    const url = `https://login.microsoftonline.com/${opts.tenantId}/oauth2/v2.0/token`;
    const res = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: opts.clientId,
        client_secret: opts.clientSecret,
        scope,
      }).toString(),
    });
    if (!res.ok) throw new Error(`Azure AD token request failed: HTTP ${res.status}`);
    const body = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!body.access_token) throw new Error("Azure AD token response missing access_token");
    cached = { token: body.access_token, exp: now() + (body.expires_in ?? 3600) };
    return cached.token;
  };
}
