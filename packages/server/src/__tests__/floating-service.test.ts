/**
 * Floating (concurrent) seat lifecycle via the service with an in-memory store
 * and a controllable clock: checkout up to the cap, deny beyond, per-device
 * idempotency, heartbeat extension, return, and automatic expiry reclaim.
 */
import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { generateEd25519KeyPair } from "@vehiclevo/licensing-shared";
import {
  buildContainer,
  LocalKeyProvider,
  FakeClock,
  DomainError,
  type AppConfig,
  type Container,
} from "@vehiclevo/licensing-server";

const KID = "key-float-test";
const TTL = 100;

function cfg(): AppConfig {
  return {
    env: "development", httpPort: 0, signingProvider: "local", localKeysDir: "",
    activeSigningKeyId: KID, tokenIssuer: "https://licensing.test",
    tokenAudience: "vehiclevo-products", tokenTtlSeconds: 3600,
    activationCodePepper: "pepper-floating-tests-123456", databaseUrl: null,
  };
}

describe("floating seats (service)", () => {
  let container: Container;
  let clock: FakeClock;

  beforeAll(() => {
    process.env.FLOATING_LEASE_TTL_SECONDS = String(TTL);
  });

  beforeEach(() => {
    const kp = generateEd25519KeyPair();
    clock = new FakeClock(1_000_000);
    const keyProvider = LocalKeyProvider.fromPems(
      [{ kid: KID, publicKeyPem: kp.publicKeyPem, privateKeyPem: kp.privateKeyPem }],
      KID,
    );
    container = buildContainer(cfg(), clock, keyProvider);
  });

  async function floatingLicense(maxSeats = 2) {
    const product = await container.service.createProduct({ key: `p-${clock.now()}`, name: "P" });
    return container.service.createLicense({
      customerId: "c", productId: product.id, edition: "pro",
      enabledFeatures: ["f1"], licenseType: "floating", maximumSeats: maxSeats,
    });
  }

  it("checks out up to the cap and denies beyond it", async () => {
    const lic = await floatingLicense(2);
    const a = await container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d1" });
    expect(a.seatsUsed).toBe(1);
    const b = await container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d2" });
    expect(b.seatsUsed).toBe(2);
    await expect(
      container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d3" }),
    ).rejects.toMatchObject({ code: "SEAT_LIMIT_REACHED" });
    // Token entitlements come back with the seat.
    expect(a.token.split(".")).toHaveLength(3);
  });

  it("is idempotent per device (re-checkout renews, does not consume a new seat)", async () => {
    const lic = await floatingLicense(2);
    const first = await container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d1" });
    clock.advance(10);
    const again = await container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d1" });
    expect(again.seatsUsed).toBe(1);
    expect(again.expiresAt).toBeGreaterThan(first.expiresAt); // renewed
  });

  it("heartbeat extends the lease; returning frees the seat", async () => {
    const lic = await floatingLicense(1);
    const seat = await container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d1" });
    clock.advance(50);
    const hb = await container.service.heartbeatSeat({ leaseId: seat.leaseId, deviceId: "d1" });
    expect(hb.expiresAt).toBe(clock.now() + TTL);
    expect(hb.expiresAt).toBeGreaterThan(seat.expiresAt);

    // Cap is 1: another device is blocked until we return.
    await expect(
      container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d2" }),
    ).rejects.toMatchObject({ code: "SEAT_LIMIT_REACHED" });
    await container.service.returnSeat({ leaseId: seat.leaseId, deviceId: "d1" });
    const d2 = await container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d2" });
    expect(d2.seatsUsed).toBe(1);
  });

  it("reclaims a seat automatically once the lease expires", async () => {
    const lic = await floatingLicense(1);
    const seat = await container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d1" });
    // Advance past the lease TTL without a heartbeat.
    clock.advance(TTL + 1);
    // The expired lease frees the seat for another device.
    const d2 = await container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d2" });
    expect(d2.seatsUsed).toBe(1);
    // Heartbeating the dead lease fails -> client must re-checkout.
    await expect(
      container.service.heartbeatSeat({ leaseId: seat.leaseId, deviceId: "d1" }),
    ).rejects.toMatchObject({ code: "LEASE_NOT_FOUND" });
  });

  it("rejects checkout on a non-floating license", async () => {
    const product = await container.service.createProduct({ key: "np", name: "NP" });
    const lic = await container.service.createLicense({
      customerId: "c", productId: product.id, edition: "e",
      enabledFeatures: [], licenseType: "subscription", maximumSeats: 5,
    });
    await expect(
      container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d1" }),
    ).rejects.toBeInstanceOf(DomainError);
  });

  it("rejects checkout on a revoked floating license", async () => {
    const lic = await floatingLicense(2);
    await container.service.revoke(lic.id, "test");
    await expect(
      container.service.checkoutSeat({ licenseId: lic.id, deviceId: "d1" }),
    ).rejects.toMatchObject({ code: "LICENSE_NOT_ACTIVE" });
  });
});
