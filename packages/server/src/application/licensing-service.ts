/**
 * Core licensing use cases — the vertical slice.
 *
 * Kept infrastructure-agnostic: everything it needs arrives via ports, so it is
 * unit-testable with in-memory adapters and a fake clock.
 */
import { DomainError } from "../domain/errors.js";
import {
  assertTransition,
  type License,
  type LicenseStatus,
} from "../domain/license.js";
import type {
  Activation,
  ActivationCodeRecord,
  AuditEvent,
  FloatingLease,
  Product,
  Revocation,
  LicenseType,
} from "../domain/types.js";
import type {
  ActivationCodeRepository,
  ActivationCodeService,
  ActivationRepository,
  AuditRepository,
  Clock,
  FloatingLeaseRepository,
  IdGenerator,
  LicenseQuery,
  LicenseRepository,
  ProductRepository,
  RevocationRepository,
} from "./ports.js";
import type { TokenIssuer } from "./token-issuer.js";

export interface LicensingServiceDeps {
  clock: Clock;
  ids: IdGenerator;
  codes: ActivationCodeService;
  products: ProductRepository;
  licenses: LicenseRepository;
  activationCodes: ActivationCodeRepository;
  activations: ActivationRepository;
  floatingLeases: FloatingLeaseRepository;
  revocations: RevocationRepository;
  audit: AuditRepository;
  tokenIssuer: TokenIssuer;
  /** Lease duration for a floating checkout/heartbeat. */
  floatingLeaseTtlSeconds: number;
}

export interface CreateLicenseInput {
  customerId: string;
  organizationId?: string | null;
  productId: string;
  edition: string;
  enabledFeatures: string[];
  licenseType: LicenseType;
  maximumSeats: number;
  notBefore?: number;
  expiresAt?: number | null;
  maintenanceExpiresAt?: number | null;
  gracePeriodSeconds?: number;
  offlineUntil?: number | null;
}

export interface ActivateInput {
  activationCode: string;
  deviceId: string;
  deviceLabel?: string | null;
  actor?: string;
}

export interface ValidateInput {
  licenseId: string;
  deviceId: string;
}

export interface ValidationResult {
  status: "valid" | "revoked" | "suspended" | "expired" | "not_active";
  token?: string;
  licenseStatus: LicenseStatus;
}

export class LicensingService {
  constructor(private readonly d: LicensingServiceDeps) {}

  async createProduct(input: { key: string; name: string }, actor = "admin"): Promise<Product> {
    const existing = await this.d.products.getByKey(input.key);
    if (existing) {
      throw new DomainError("VALIDATION", `product key '${input.key}' already exists`);
    }
    const product: Product = {
      id: this.d.ids.next("prod"),
      key: input.key,
      name: input.name,
      createdAt: this.d.clock.now(),
    };
    await this.d.products.create(product);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "product.created",
      licenseId: null,
      actor,
      at: product.createdAt,
      metadata: { productKey: product.key },
    });
    return product;
  }

  async createLicense(input: CreateLicenseInput, actor = "admin"): Promise<License> {
    const product = await this.d.products.get(input.productId);
    if (!product) throw new DomainError("NOT_FOUND", "product not found");
    if (input.maximumSeats < 1) {
      throw new DomainError("VALIDATION", "maximumSeats must be >= 1");
    }
    const now = this.d.clock.now();
    const license: License = {
      id: this.d.ids.next("lic"),
      customerId: input.customerId,
      organizationId: input.organizationId ?? null,
      productId: input.productId,
      edition: input.edition,
      enabledFeatures: input.enabledFeatures,
      licenseType: input.licenseType,
      status: "active",
      maximumSeats: input.maximumSeats,
      notBefore: input.notBefore ?? now,
      expiresAt: input.expiresAt ?? null,
      maintenanceExpiresAt: input.maintenanceExpiresAt ?? null,
      gracePeriodSeconds: input.gracePeriodSeconds ?? 0,
      offlineUntil: input.offlineUntil ?? null,
      createdAt: now,
      updatedAt: now,
      version: 1,
    };
    await this.d.licenses.create(license);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "license.created",
      licenseId: license.id,
      actor,
      at: now,
      metadata: { productId: license.productId, edition: license.edition },
    });
    return license;
  }

  /** Returns the PLAINTEXT activation code exactly once. Only its hash is stored. */
  async generateActivationCode(
    licenseId: string,
    maxActivations = 1,
    actor = "admin",
  ): Promise<{ activationCode: string; record: ActivationCodeRecord }> {
    const license = await this.d.licenses.get(licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");
    const { plaintext, hash } = this.d.codes.generate();
    const record: ActivationCodeRecord = {
      id: this.d.ids.next("ac"),
      licenseId,
      codeHash: hash,
      status: "unused",
      maxActivations,
      usedActivations: 0,
      createdAt: this.d.clock.now(),
      consumedAt: null,
    };
    await this.d.activationCodes.create(record);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "activation_code.generated",
      licenseId,
      actor,
      at: record.createdAt,
      metadata: { maxActivations },
    });
    // NOTE: plaintext is returned to the caller (admin UI) and never logged.
    return { activationCode: plaintext, record };
  }

  /** Client activation: consume a code, register the device, return a signed token. */
  async activate(input: ActivateInput): Promise<{ token: string; license: License }> {
    const hash = this.d.codes.hash(input.activationCode);
    const code = await this.d.activationCodes.findByHash(hash);
    if (!code || code.status === "revoked") {
      throw new DomainError("ACTIVATION_CODE_INVALID", "activation code is invalid");
    }
    const license = await this.d.licenses.get(code.licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");
    if (license.status !== "active") {
      throw new DomainError("LICENSE_NOT_ACTIVE", `license is ${license.status}`);
    }

    // Idempotency: re-activating the same device returns a fresh token, no double-count.
    const existing = await this.d.activations.findActiveByDevice(
      license.id,
      input.deviceId,
    );
    if (!existing) {
      if (code.usedActivations >= code.maxActivations) {
        throw new DomainError("ACTIVATION_CODE_CONSUMED", "activation code exhausted");
      }
      const now = this.d.clock.now();
      const activation: Activation = {
        id: this.d.ids.next("act"),
        licenseId: license.id,
        activationCodeId: code.id,
        deviceId: input.deviceId,
        deviceLabel: input.deviceLabel ?? null,
        status: "active",
        activatedAt: now,
        lastSeenAt: now,
        deactivatedAt: null,
      };
      // Atomic seat-cap enforcement: the repository refuses the insert if the
      // active-seat count is already at the limit (race-free under concurrency).
      const created = await this.d.activations.createIfUnderSeatLimit(
        activation,
        license.maximumSeats,
      );
      if (!created) {
        throw new DomainError("SEAT_LIMIT_REACHED", "maximum seats reached");
      }
      code.usedActivations += 1;
      if (code.usedActivations >= code.maxActivations) {
        code.status = "consumed";
        code.consumedAt = now;
      }
      await this.d.activationCodes.update(code);
      await this.d.audit.append({
        id: this.d.ids.next("evt"),
        type: "license.activated",
        licenseId: license.id,
        actor: `sdk:${input.deviceId}`,
        at: now,
        metadata: { activationId: activation.id },
      });
    }

    const issued = await this.d.tokenIssuer.issue(license);
    return { token: issued.token, license };
  }

  /** Online validation — authoritative liveness check (revocation/suspension/expiry). */
  async validate(input: ValidateInput): Promise<ValidationResult> {
    const license = await this.d.licenses.get(input.licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");

    const now = this.d.clock.now();

    if (await this.d.revocations.isRevoked(license.id)) {
      return { status: "revoked", licenseStatus: "revoked" };
    }
    if (license.status === "suspended") {
      return { status: "suspended", licenseStatus: "suspended" };
    }
    if (license.status !== "active") {
      return { status: "not_active", licenseStatus: license.status };
    }
    if (license.expiresAt !== null && now > license.expiresAt + license.gracePeriodSeconds) {
      return { status: "expired", licenseStatus: "expired" };
    }

    // Touch last-seen for the device (best-effort presence tracking).
    const act = await this.d.activations.findActiveByDevice(license.id, input.deviceId);
    if (act) {
      act.lastSeenAt = now;
      await this.d.activations.update(act);
    }

    const issued = await this.d.tokenIssuer.issue(license);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "license.validated",
      licenseId: license.id,
      actor: `sdk:${input.deviceId}`,
      at: now,
      metadata: { deviceKnown: Boolean(act) },
    });
    return { status: "valid", token: issued.token, licenseStatus: "active" };
  }

  async revoke(licenseId: string, reason: string, actor = "admin"): Promise<void> {
    const license = await this.d.licenses.get(licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");
    assertTransition(license.status, "revoked");
    const now = this.d.clock.now();
    await this.d.revocations.add({ licenseId, reason, revokedAt: now });
    const prevVersion = license.version;
    license.status = "revoked";
    license.updatedAt = now;
    license.version += 1;
    await this.d.licenses.update(license, prevVersion);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "license.revoked",
      licenseId,
      actor,
      at: now,
      metadata: { reason },
    });
  }

  /** Temporarily disable a license (reversible). */
  async suspend(licenseId: string, reason: string, actor = "admin"): Promise<License> {
    return this.transition(licenseId, "suspended", "license.suspended", { reason }, actor);
  }

  /** Re-enable a suspended license. */
  async resume(licenseId: string, actor = "admin"): Promise<License> {
    return this.transition(licenseId, "active", "license.resumed", {}, actor);
  }

  /**
   * Renew: extend expiry (and optionally maintenance) and ensure the license is
   * active. Renewing an expired license moves it back to active.
   */
  async renew(
    licenseId: string,
    input: { expiresAt: number | null; maintenanceExpiresAt?: number | null },
    actor = "admin",
  ): Promise<License> {
    const license = await this.d.licenses.get(licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");
    if (license.status === "revoked") {
      throw new DomainError("INVALID_STATE_TRANSITION", "cannot renew a revoked license");
    }
    const now = this.d.clock.now();
    const prevVersion = license.version;
    license.expiresAt = input.expiresAt;
    if (input.maintenanceExpiresAt !== undefined) {
      license.maintenanceExpiresAt = input.maintenanceExpiresAt;
    }
    if (license.status === "expired") license.status = "active";
    license.updatedAt = now;
    license.version += 1;
    await this.d.licenses.update(license, prevVersion);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "license.renewed",
      licenseId,
      actor,
      at: now,
      metadata: { expiresAt: input.expiresAt },
    });
    return license;
  }

  // --- read side (portal) ---

  async listProducts(): Promise<Product[]> {
    return this.d.products.list();
  }

  async listLicenses(query: LicenseQuery): Promise<{ items: License[]; total: number }> {
    return this.d.licenses.list(query);
  }

  /** Full detail for one license: activations, code metadata (never plaintext), revocation. */
  async getLicenseDetail(licenseId: string): Promise<{
    license: License;
    activations: Activation[];
    activationCodes: Array<Omit<ActivationCodeRecord, "codeHash">>;
    floatingLeases: FloatingLease[];
    revocation: Revocation | null;
    audit: AuditEvent[];
  }> {
    const license = await this.d.licenses.get(licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");
    const [activations, codes, floatingLeases, revocation, audit] = await Promise.all([
      this.d.activations.listByLicense(licenseId),
      this.d.activationCodes.listByLicense(licenseId),
      this.d.floatingLeases.listActive(licenseId, this.d.clock.now()),
      this.d.revocations.get(licenseId),
      this.d.audit.query({ licenseId, limit: 100 }),
    ]);
    // Strip the hash so the portal never receives code material.
    const activationCodes = codes.map(({ codeHash, ...rest }) => rest);
    return { license, activations, activationCodes, floatingLeases, revocation, audit };
  }

  async listAuditEvents(licenseId?: string): Promise<AuditEvent[]> {
    return this.d.audit.query({ licenseId, limit: 200 });
  }

  // --- customer self-service (STRICTLY scoped to the caller's customerId) ---

  /** Throws NOT_FOUND if the license does not exist OR is not owned by the caller. */
  private async requireOwnedLicense(customerId: string, licenseId: string): Promise<License> {
    const license = await this.d.licenses.get(licenseId);
    // Same error whether missing or not-owned — never leak another customer's ids.
    if (!license || license.customerId !== customerId) {
      throw new DomainError("NOT_FOUND", "license not found");
    }
    return license;
  }

  async getCustomerLicenses(customerId: string): Promise<License[]> {
    const { items } = await this.d.licenses.list({ customerId, limit: 200 });
    return items;
  }

  /** Customer-safe detail: entitlements, dates, seat usage, own devices. No internal audit. */
  async getCustomerLicenseDetail(
    customerId: string,
    licenseId: string,
  ): Promise<{
    license: License;
    seatsUsed: number;
    devices: Activation[];
    revoked: boolean;
  }> {
    const license = await this.requireOwnedLicense(customerId, licenseId);
    const [devices, revoked] = await Promise.all([
      this.d.activations.listByLicense(licenseId),
      this.d.revocations.isRevoked(licenseId),
    ]);
    const seatsUsed = devices.filter((d) => d.status === "active").length;
    return { license, seatsUsed, devices, revoked };
  }

  /** Self-service device deactivation (frees a seat; enables transfer). */
  async deactivateDevice(
    customerId: string,
    licenseId: string,
    activationId: string,
  ): Promise<void> {
    await this.requireOwnedLicense(customerId, licenseId);
    const activation = await this.d.activations.get(activationId);
    if (!activation || activation.licenseId !== licenseId) {
      throw new DomainError("NOT_FOUND", "device not found");
    }
    if (activation.status === "active") {
      const now = this.d.clock.now();
      activation.status = "deactivated";
      activation.deactivatedAt = now;
      await this.d.activations.update(activation);
      await this.d.audit.append({
        id: this.d.ids.next("evt"),
        type: "device.deactivated",
        licenseId,
        actor: `customer:${customerId}`,
        at: now,
        metadata: { activationId, self_service: true },
      });
    }
  }

  /** Record a customer's activation-reset request for support to action. */
  async requestActivationReset(
    customerId: string,
    licenseId: string,
    note = "",
  ): Promise<void> {
    await this.requireOwnedLicense(customerId, licenseId);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "activation_reset.requested",
      licenseId,
      actor: `customer:${customerId}`,
      at: this.d.clock.now(),
      metadata: { note: note.slice(0, 500) },
    });
  }

  /** Issue a downloadable signed license file (token) for an owned, live license. */
  async downloadLicenseFile(
    customerId: string,
    licenseId: string,
  ): Promise<{ token: string; licenseId: string }> {
    const license = await this.requireOwnedLicense(customerId, licenseId);
    if (license.status === "revoked" || (await this.d.revocations.isRevoked(licenseId))) {
      throw new DomainError("LICENSE_NOT_ACTIVE", "license is revoked");
    }
    const issued = await this.d.tokenIssuer.issue(license);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "license_file.downloaded",
      licenseId,
      actor: `customer:${customerId}`,
      at: this.d.clock.now(),
      metadata: { tokenId: issued.tokenId },
    });
    return { token: issued.token, licenseId };
  }

  // --- floating (concurrent) seats ---

  /** Validate a license is usable for a floating checkout, else throw. */
  private async requireCheckoutableLicense(licenseId: string): Promise<License> {
    const license = await this.d.licenses.get(licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");
    if (license.licenseType !== "floating") {
      throw new DomainError("VALIDATION", "license is not a floating license");
    }
    if (await this.d.revocations.isRevoked(license.id)) {
      throw new DomainError("LICENSE_NOT_ACTIVE", "license is revoked");
    }
    if (license.status !== "active") {
      throw new DomainError("LICENSE_NOT_ACTIVE", `license is ${license.status}`);
    }
    const now = this.d.clock.now();
    if (license.expiresAt !== null && now > license.expiresAt + license.gracePeriodSeconds) {
      throw new DomainError("LICENSE_NOT_ACTIVE", "license is expired");
    }
    return license;
  }

  /** Check out a concurrent seat (atomic). Returns the lease + a signed token. */
  async checkoutSeat(input: {
    licenseId: string;
    deviceId: string;
    deviceLabel?: string | null;
  }): Promise<{
    leaseId: string;
    expiresAt: number;
    seatsUsed: number;
    maximumSeats: number;
    token: string;
  }> {
    const license = await this.requireCheckoutableLicense(input.licenseId);
    const now = this.d.clock.now();
    const lease = await this.d.floatingLeases.acquire({
      id: this.d.ids.next("lease"),
      licenseId: license.id,
      deviceId: input.deviceId,
      deviceLabel: input.deviceLabel ?? null,
      now,
      ttlSeconds: this.d.floatingLeaseTtlSeconds,
      maxSeats: license.maximumSeats,
    });
    if (!lease) {
      throw new DomainError("SEAT_LIMIT_REACHED", "no concurrent seats available");
    }
    const [seatsUsed, issued] = await Promise.all([
      this.d.floatingLeases.countActive(license.id, now),
      this.d.tokenIssuer.issue(license),
    ]);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "floating.checkout",
      licenseId: license.id,
      actor: `sdk:${input.deviceId}`,
      at: now,
      metadata: { leaseId: lease.id, seatsUsed },
    });
    return {
      leaseId: lease.id,
      expiresAt: lease.expiresAt,
      seatsUsed,
      maximumSeats: license.maximumSeats,
      token: issued.token,
    };
  }

  /** Extend a held lease. Throws LEASE_NOT_FOUND if it has expired/been returned. */
  async heartbeatSeat(input: {
    leaseId: string;
    deviceId: string;
  }): Promise<{ leaseId: string; expiresAt: number }> {
    const now = this.d.clock.now();
    const lease = await this.d.floatingLeases.heartbeat({
      leaseId: input.leaseId,
      deviceId: input.deviceId,
      now,
      ttlSeconds: this.d.floatingLeaseTtlSeconds,
    });
    if (!lease) {
      throw new DomainError("LEASE_NOT_FOUND", "lease is no longer active; re-checkout required");
    }
    return { leaseId: lease.id, expiresAt: lease.expiresAt };
  }

  /** Return a concurrent seat (idempotent). */
  async returnSeat(input: { leaseId: string; deviceId: string }): Promise<void> {
    const now = this.d.clock.now();
    const released = await this.d.floatingLeases.release(input.leaseId, input.deviceId, now);
    if (released) {
      await this.d.audit.append({
        id: this.d.ids.next("evt"),
        type: "floating.return",
        licenseId: null,
        actor: `sdk:${input.deviceId}`,
        at: now,
        metadata: { leaseId: input.leaseId },
      });
    }
  }

  async listActiveLeases(licenseId: string): Promise<FloatingLease[]> {
    return this.d.floatingLeases.listActive(licenseId, this.d.clock.now());
  }

  private async transition(
    licenseId: string,
    to: LicenseStatus,
    eventType: AuditEvent["type"],
    metadata: Record<string, string | number | boolean | null>,
    actor: string,
  ): Promise<License> {
    const license = await this.d.licenses.get(licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");
    assertTransition(license.status, to);
    const now = this.d.clock.now();
    const prevVersion = license.version;
    license.status = to;
    license.updatedAt = now;
    license.version += 1;
    await this.d.licenses.update(license, prevVersion);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: eventType,
      licenseId,
      actor,
      at: now,
      metadata,
    });
    return license;
  }
}
