/**
 * Offline (air-gapped) activation round-trip:
 *   SDK.generateOfflineRequest -> POST /offline/response -> SDK.importOfflineResponse
 * plus idempotency/replay, device binding, tampering, and seat limits. The SDK
 * side uses a transport that THROWS, proving import needs no network.
 */
import { describe, it, expect, beforeAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { generateEd25519KeyPair, type OfflineResponseFile } from "@vehiclevo/licensing-shared";
import {
  buildContainer,
  buildHttpServer,
  LocalKeyProvider,
  FakeClock,
  type AppConfig,
} from "@vehiclevo/licensing-server";
import {
  LicensingClient,
  InMemoryTokenStore,
  LicensingErrorCode,
  type HttpClient,
} from "@vehiclevo/licensing-sdk";

const KID = "key-offline-test";
const ADMIN = "admin-offline-key-123456";
const ISSUER = "https://licensing.test";
const AUDIENCE = "vehiclevo-products";
const NOW = 1_700_000_000;

const adminH = { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" };
const offlineHttp: HttpClient = { async post() { throw new Error("air-gapped: no network"); } };

describe("offline activation files", () => {
  let app: FastifyInstance;
  let publicKeyPem: string;
  let productId: string;

  async function newLicense(maxSeats = 2) {
    return (
      await app.inject({
        method: "POST", url: "/api/v1/admin/licenses", headers: adminH,
        payload: {
          customerId: "c", productId, edition: "pro", enabledFeatures: ["export_pdf"],
          licenseType: "subscription", maximumSeats: maxSeats, expiresAt: NOW + 30 * 86400,
        },
      })
    ).json().id as string;
  }
  async function newCode(licenseId: string, max = 5) {
    return (
      await app.inject({
        method: "POST", url: `/api/v1/admin/licenses/${licenseId}/activation-codes`,
        headers: adminH, payload: { maxActivations: max },
      })
    ).json().activationCode as string;
  }
  function sdk(deviceId: string) {
    return LicensingClient.initialize({
      expectedIssuer: ISSUER, expectedAudience: AUDIENCE, deviceId,
      publicKeys: [{ kid: KID, pem: publicKeyPem }],
      http: offlineHttp, store: new InMemoryTokenStore(), clock: { now: () => NOW },
    });
  }
  async function getResponse(request: unknown): Promise<{ status: number; body: OfflineResponseFile }> {
    const res = await app.inject({
      method: "POST", url: "/api/v1/offline/response",
      headers: { "content-type": "application/json" }, payload: request as object,
    });
    return { status: res.statusCode, body: res.json() };
  }

  beforeAll(async () => {
    process.env.ADMIN_API_KEY = ADMIN;
    const kp = generateEd25519KeyPair();
    publicKeyPem = kp.publicKeyPem;
    const keyProvider = LocalKeyProvider.fromPems(
      [{ kid: KID, publicKeyPem: kp.publicKeyPem, privateKeyPem: kp.privateKeyPem }],
      KID,
    );
    const cfg: AppConfig = {
      env: "development", httpPort: 0, signingProvider: "local", localKeysDir: "",
      activeSigningKeyId: KID, tokenIssuer: ISSUER, tokenAudience: AUDIENCE,
      tokenTtlSeconds: 3600, activationCodePepper: "pepper-offline-tests-123456", databaseUrl: null,
    };
    app = buildHttpServer(buildContainer(cfg, new FakeClock(NOW), keyProvider));
    await app.ready();
    productId = (
      await app.inject({ method: "POST", url: "/api/v1/admin/products", headers: adminH, payload: { key: "vv-off", name: "Off" } })
    ).json().id;
  });

  it("completes an air-gapped round-trip and gates a feature offline", async () => {
    const licenseId = await newLicense();
    const code = await newCode(licenseId);
    const client = await sdk("air-gapped-device-1");

    const request = client.generateOfflineRequest(code);
    expect(request.kind).toBe("offline-request");

    const { status, body } = await getResponse(request);
    expect(status).toBe(200);
    expect(body.kind).toBe("offline-response");
    expect(body.licenseId).toBe(licenseId);

    // Import with NO network; feature gating works offline.
    const snap = await client.importOfflineResponse(body);
    expect(snap.ok).toBe(true);
    expect(client.hasFeature("export_pdf")).toBe(true);
    expect(client.getOfflineDaysRemaining()).toBeGreaterThan(0);
  });

  it("is idempotent by requestId (no extra seat on re-submit)", async () => {
    const licenseId = await newLicense(1);
    const code = await newCode(licenseId);
    const client = await sdk("dev-idem");
    const request = client.generateOfflineRequest(code);

    const first = await getResponse(request);
    const second = await getResponse(request);
    expect(second.status).toBe(200);
    expect(second.body.token).toBe(first.body.token); // same response returned

    const detail = (
      await app.inject({ method: "GET", url: `/api/v1/admin/licenses/${licenseId}`, headers: adminH })
    ).json();
    expect(detail.activations.filter((a: { status: string }) => a.status === "active")).toHaveLength(1);
  });

  it("rejects an offline file on a different device (device binding)", async () => {
    const licenseId = await newLicense();
    const code = await newCode(licenseId);
    const clientA = await sdk("device-A");
    const { body } = await getResponse(clientA.generateOfflineRequest(code));

    const clientB = await sdk("device-B");
    await expect(clientB.importOfflineResponse(body)).rejects.toMatchObject({
      code: LicensingErrorCode.DeviceMismatch,
    });
  });

  it("rejects a tampered response token", async () => {
    const licenseId = await newLicense();
    const code = await newCode(licenseId);
    const client = await sdk("device-tamper");
    const { body } = await getResponse(client.generateOfflineRequest(code));

    const [h, p, s] = body.token.split(".") as [string, string, string];
    const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    claims.enabledFeatures.push("enterprise_only");
    const forged = { ...body, token: `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}` };
    await expect(client.importOfflineResponse(forged)).rejects.toMatchObject({
      code: LicensingErrorCode.SignatureInvalid,
    });
  });

  it("enforces the seat limit across offline activations", async () => {
    const licenseId = await newLicense(1);
    const code = await newCode(licenseId);
    const c1 = await sdk("off-seat-1");
    const c2 = await sdk("off-seat-2");
    expect((await getResponse(c1.generateOfflineRequest(code))).status).toBe(200);
    // Second distinct device exceeds maxSeats=1.
    expect((await getResponse(c2.generateOfflineRequest(code))).status).toBe(409);
  });
});
