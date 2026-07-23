/**
 * Postgres integration tests. Skipped unless TEST_DATABASE_URL points at a
 * reachable Postgres (so the default `npm test` stays dependency-free). Proves
 * migrations-from-clean, CRUD round-trips, optimistic concurrency, and — the
 * key guarantee — that concurrent activations cannot oversell seats.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateEd25519KeyPair } from "@vehiclevo/licensing-shared";
import {
  buildContainer,
  runMigrations,
  LocalKeyProvider,
  FakeClock,
  PgLicenseRepository,
  type AppConfig,
  type Container,
} from "@vehiclevo/licensing-server";

const URL = process.env.TEST_DATABASE_URL;
const d = URL ? describe : describe.skip;

const KID = "key-pg-test";

function makeCfg(): AppConfig {
  return {
    env: "development",
    httpPort: 0,
    signingProvider: "local",
    localKeysDir: "",
    activeSigningKeyId: KID,
    tokenIssuer: "https://licensing.test",
    tokenAudience: "vehiclevo-products",
    tokenTtlSeconds: 3600,
    activationCodePepper: "pepper-for-pg-tests-1234567890",
    databaseUrl: URL ?? null,
  };
}

d("Postgres persistence", () => {
  let container: Container;
  let clock: FakeClock;

  beforeAll(async () => {
    const kp = generateEd25519KeyPair();
    clock = new FakeClock(1_700_000_000);
    const keyProvider = LocalKeyProvider.fromPems(
      [{ kid: KID, publicKeyPem: kp.publicKeyPem, privateKeyPem: kp.privateKeyPem }],
      KID,
    );
    container = buildContainer(makeCfg(), clock, keyProvider);
    // Start from a truly clean database, then migrate.
    await container.pool!.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
    await runMigrations(container.pool!);
  });

  afterAll(async () => {
    await container?.close();
  });

  it("runs migrations from clean and is idempotent", async () => {
    const again = await runMigrations(container.pool!);
    expect(again.applied).toHaveLength(0);
    expect(again.skipped.length).toBeGreaterThan(0);
    const t = await container.pool!.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name='licenses'",
    );
    expect(t.rowCount).toBe(1);
  });

  it("round-trips the full activate/validate/revoke flow through Postgres", async () => {
    const product = await container.service.createProduct({ key: "vv-pg", name: "PG Tool" });
    const license = await container.service.createLicense({
      customerId: "cust_pg",
      productId: product.id,
      edition: "pro",
      enabledFeatures: ["export_pdf"],
      licenseType: "subscription",
      maximumSeats: 3,
      expiresAt: clock.now() + 86400,
    });
    const { activationCode } = await container.service.generateActivationCode(license.id, 1);

    const activated = await container.service.activate({
      activationCode,
      deviceId: "device-pg-1",
    });
    expect(activated.token.split(".")).toHaveLength(3);

    const valid = await container.service.validate({
      licenseId: license.id,
      deviceId: "device-pg-1",
    });
    expect(valid.status).toBe("valid");

    // Detail read side: activation present, code hash NOT exposed.
    const detail = await container.service.getLicenseDetail(license.id);
    expect(detail.activations).toHaveLength(1);
    expect(JSON.stringify(detail.activationCodes)).not.toContain("codeHash");

    await container.service.revoke(license.id, "test");
    const afterRevoke = await container.service.validate({
      licenseId: license.id,
      deviceId: "device-pg-1",
    });
    expect(afterRevoke.status).toBe("revoked");
  });

  it("enforces optimistic concurrency on license updates", async () => {
    const product = await container.service.createProduct({ key: "vv-occ", name: "OCC" });
    const license = await container.service.createLicense({
      customerId: "c",
      productId: product.id,
      edition: "e",
      enabledFeatures: [],
      licenseType: "subscription",
      maximumSeats: 1,
    });
    // Two writers read the same version, both try to persist against it.
    const repo = new PgLicenseRepository(container.pool!);
    const a = (await repo.get(license.id))!;
    const b = (await repo.get(license.id))!;
    a.status = "suspended";
    a.version += 1;
    await repo.update(a, license.version);
    b.status = "revoked";
    b.version += 1;
    await expect(repo.update(b, license.version)).rejects.toThrow(/concurrent modification/);
  });

  it("never oversells seats under concurrent activation (atomic seat cap)", async () => {
    const product = await container.service.createProduct({ key: "vv-seats-pg", name: "Seats" });
    const license = await container.service.createLicense({
      customerId: "c",
      productId: product.id,
      edition: "e",
      enabledFeatures: [],
      licenseType: "floating",
      maximumSeats: 2,
    });
    // One code with plenty of activations so the SEAT cap (not the code) is the limiter.
    const { activationCode } = await container.service.generateActivationCode(license.id, 100);

    // Fire 8 concurrent activations from distinct devices.
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, (_, i) =>
        container.service.activate({ activationCode, deviceId: `dev-${i}` }),
      ),
    );
    const ok = results.filter((r) => r.status === "fulfilled").length;
    const seatErrors = results.filter(
      (r) => r.status === "rejected" && /maximum seats/.test(String(r.reason?.message)),
    ).length;

    expect(ok).toBe(2); // exactly the cap
    expect(seatErrors).toBe(6);

    const count = await container.pool!.query<{ n: string }>(
      "SELECT count(*)::int AS n FROM activations WHERE license_id=$1 AND status='active'",
      [license.id],
    );
    expect(Number(count.rows[0]!.n)).toBe(2); // DB agrees — no oversell
  });

  it("never exceeds the concurrent-seat cap under parallel floating checkout", async () => {
    const product = await container.service.createProduct({ key: "vv-float-pg", name: "Float" });
    const license = await container.service.createLicense({
      customerId: "c", productId: product.id, edition: "e", enabledFeatures: [],
      licenseType: "floating", maximumSeats: 3,
    });
    // 10 distinct devices race to check out a concurrent seat.
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, (_, i) =>
        container.service.checkoutSeat({ licenseId: license.id, deviceId: `fdev-${i}` }),
      ),
    );
    const ok = results.filter((r) => r.status === "fulfilled").length;
    expect(ok).toBe(3);

    const active = await container.pool!.query<{ n: string }>(
      "SELECT count(*)::int AS n FROM floating_leases WHERE license_id=$1 AND released_at IS NULL AND expires_at > $2",
      [license.id, 1_700_000_000],
    );
    expect(Number(active.rows[0]!.n)).toBe(3); // DB agrees — cap held
  });

  it("never over-consumes an activation code under parallel activation", async () => {
    const product = await container.service.createProduct({ key: "vv-code-race", name: "CodeRace" });
    const license = await container.service.createLicense({
      customerId: "c", productId: product.id, edition: "e", enabledFeatures: [],
      licenseType: "device", maximumSeats: 50, // seats NOT the limiter here
    });
    // A single-use code raced by 6 distinct devices: exactly one may win.
    const { activationCode, record } = await container.service.generateActivationCode(license.id, 1);
    const results = await Promise.allSettled(
      Array.from({ length: 6 }, (_, i) =>
        container.service.activate({ activationCode, deviceId: `race-dev-${i}` }),
      ),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);

    const row = await container.pool!.query(
      "SELECT used_activations, max_activations, status FROM activation_codes WHERE id=$1",
      [record.id],
    );
    expect(Number(row.rows[0]!.used_activations)).toBe(1); // never exceeds max
    expect(row.rows[0]!.status).toBe("consumed");
  });

  it("grants exactly one trial per device under concurrent requests (unique constraint)", async () => {
    await container.service.createProduct({
      key: "vv-trial-pg",
      name: "Trial PG",
      trial: { enabled: true, days: 7, features: ["basic"] },
    });
    // The same device races 5 concurrent trial starts.
    const results = await Promise.allSettled(
      Array.from({ length: 5 }, () =>
        container.service.startTrial({ productKey: "vv-trial-pg", deviceId: "pg-trial-dev" }),
      ),
    );
    const ok = results.filter((r) => r.status === "fulfilled") as PromiseFulfilledResult<{
      license: { id: string };
    }>[];
    expect(ok.length).toBe(5); // all succeed (winner creates, losers resume)
    const licenseIds = new Set(ok.map((r) => r.value.license.id));
    expect(licenseIds.size).toBe(1); // ...but they all share ONE license

    const rows = await container.pool!.query<{ n: string }>(
      "SELECT count(*)::int AS n FROM trials WHERE device_id='pg-trial-dev'",
    );
    expect(Number(rows.rows[0]!.n)).toBe(1); // exactly one trial row
  });
});
