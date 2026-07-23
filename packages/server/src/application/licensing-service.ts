/**
 * Core licensing use cases — the vertical slice.
 *
 * Kept infrastructure-agnostic: everything it needs arrives via ports, so it is
 * unit-testable with in-memory adapters and a fake clock.
 */
import { DomainError } from "../domain/errors.js";
import {
  hashDeviceBinding,
  OFFLINE_SCHEMA_VERSION,
  type OfflineRequestFile,
  type OfflineResponseFile,
} from "@vehiclevo/licensing-shared";
import {
  assertTransition,
  type License,
  type LicenseStatus,
} from "../domain/license.js";
import {
  DEFAULT_TRIAL_POLICY,
  type Activation,
  type ActivationCodeRecord,
  type AuditEvent,
  type FloatingLease,
  type Product,
  type Revocation,
  type LicenseType,
  type TrialPolicy,
  type TrialRecord,
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
  OfflineRepository,
  ProductRepository,
  RevocationRepository,
  TrialRepository,
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
  offline: OfflineRepository;
  trials: TrialRepository;
  revocations: RevocationRepository;
  audit: AuditRepository;
  tokenIssuer: TokenIssuer;
  /** Lease duration for a floating checkout/heartbeat. */
  floatingLeaseTtlSeconds: number;
  /** Max validity (days) for an offline token when the license has no expiry. */
  offlineTokenMaxDays: number;
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
  status:
    | "valid"
    | "revoked"
    | "suspended"
    | "expired"
    | "not_active"
    | "device_not_activated";
  token?: string;
  licenseStatus: LicenseStatus;
}

export class LicensingService {
  constructor(private readonly d: LicensingServiceDeps) {}

  async createProduct(
    input: { key: string; name: string; trial?: Partial<TrialPolicy> },
    actor = "admin",
  ): Promise<Product> {
    const existing = await this.d.products.getByKey(input.key);
    if (existing) {
      throw new DomainError("VALIDATION", `product key '${input.key}' already exists`);
    }
    const trial: TrialPolicy = { ...DEFAULT_TRIAL_POLICY, ...input.trial };
    if (trial.enabled && (!Number.isInteger(trial.days) || trial.days < 1 || trial.days > 365)) {
      throw new DomainError("VALIDATION", "trial.days must be an integer between 1 and 365");
    }
    const product: Product = {
      id: this.d.ids.next("prod"),
      key: input.key,
      name: input.name,
      createdAt: this.d.clock.now(),
      trial,
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
      const now = this.d.clock.now();
      // Atomically consume one code use FIRST (conditional update — race-free),
      // so concurrent activations can never exceed maxActivations.
      const consumed = await this.d.activationCodes.consumeUse(code.id, now);
      if (!consumed) {
        throw new DomainError("ACTIVATION_CODE_CONSUMED", "activation code exhausted");
      }
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
        // Give the consumed code use back — the activation did not happen.
        await this.d.activationCodes.releaseUse(code.id);
        throw new DomainError("SEAT_LIMIT_REACHED", "maximum seats reached");
      }
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

    // The device must hold an ACTIVE activation. Without this check a device
    // that was deactivated (freeing its seat) — or that never activated at
    // all — would keep receiving fresh signed tokens forever.
    const act = await this.d.activations.findActiveByDevice(license.id, input.deviceId);
    if (!act) {
      return { status: "device_not_activated", licenseStatus: license.status };
    }
    act.lastSeenAt = now;
    await this.d.activations.update(act);

    const issued = await this.d.tokenIssuer.issue(license);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "license.validated",
      licenseId: license.id,
      actor: `sdk:${input.deviceId}`,
      at: now,
      metadata: {},
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

  /**
   * SDK-initiated deactivation. The HTTP layer authenticates the caller by
   * verifying it presents a validly signed license token (proof of possession)
   * for this licenseId. Idempotent: deactivating an unknown/inactive device is
   * a no-op.
   */
  async deactivateFromClient(licenseId: string, deviceId: string): Promise<void> {
    const activation = await this.d.activations.findActiveByDevice(licenseId, deviceId);
    if (!activation) return;
    const now = this.d.clock.now();
    activation.status = "deactivated";
    activation.deactivatedAt = now;
    await this.d.activations.update(activation);
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "device.deactivated",
      licenseId,
      actor: `sdk:${deviceId}`,
      at: now,
      metadata: { activationId: activation.id, self_service: true },
    });
  }

  // --- self-service trials ---

  /**
   * Start (or resume) a free trial for a product on a device. One trial per
   * (product, device), enforced atomically by the trial registry's unique
   * constraint. While the trial is still running, repeat calls resume it
   * (reinstall keeps the remaining days); after it ends, TRIAL_ALREADY_USED.
   * The issued token is device-bound so the trial license cannot be copied.
   */
  async startTrial(input: {
    productKey: string;
    deviceId: string;
    deviceLabel?: string | null;
  }): Promise<{ token: string; license: License }> {
    const product = await this.d.products.getByKey(input.productKey);
    if (!product || !product.trial.enabled) {
      throw new DomainError("TRIAL_NOT_AVAILABLE", "no trial is available for this product");
    }
    const existing = await this.d.trials.findByProductAndDevice(product.id, input.deviceId);
    if (existing) return this.resumeTrial(existing.licenseId, input.deviceId);

    const now = this.d.clock.now();
    const license: License = {
      id: this.d.ids.next("lic"),
      customerId: `trial:${input.deviceId}`,
      organizationId: null,
      productId: product.id,
      edition: product.trial.edition,
      enabledFeatures: product.trial.features,
      licenseType: "trial",
      status: "active",
      maximumSeats: 1,
      notBefore: now,
      expiresAt: now + product.trial.days * 86400,
      maintenanceExpiresAt: null,
      gracePeriodSeconds: 0,
      offlineUntil: null,
      createdAt: now,
      updatedAt: now,
      version: 1,
    };
    await this.d.licenses.create(license);

    const record: TrialRecord = {
      id: this.d.ids.next("trial"),
      productId: product.id,
      licenseId: license.id,
      deviceId: input.deviceId,
      createdAt: now,
    };
    const claimed = await this.d.trials.create(record);
    if (!claimed) {
      // Lost a race with a concurrent request from the same device: retire the
      // orphan license we just created and resume the winner's trial instead.
      const prevVersion = license.version;
      license.status = "revoked";
      license.updatedAt = now;
      license.version += 1;
      await this.d.licenses.update(license, prevVersion);
      const winner = await this.d.trials.findByProductAndDevice(product.id, input.deviceId);
      if (!winner) throw new DomainError("TRIAL_NOT_AVAILABLE", "trial state conflict");
      return this.resumeTrial(winner.licenseId, input.deviceId);
    }

    // Register the device so /validate works for the trial (single seat).
    await this.d.activations.createIfUnderSeatLimit(
      {
        id: this.d.ids.next("act"),
        licenseId: license.id,
        activationCodeId: null,
        deviceId: input.deviceId,
        deviceLabel: input.deviceLabel ?? null,
        status: "active",
        activatedAt: now,
        lastSeenAt: now,
        deactivatedAt: null,
      },
      1,
    );
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "trial.started",
      licenseId: license.id,
      actor: `sdk:${input.deviceId}`,
      at: now,
      metadata: { productKey: product.key, days: product.trial.days },
    });

    const issued = await this.d.tokenIssuer.issue(license, {
      deviceBinding: hashDeviceBinding(input.deviceId),
    });
    return { token: issued.token, license };
  }

  /** Resume a still-running trial; deny once it has ended in any way. */
  private async resumeTrial(
    licenseId: string,
    deviceId: string,
  ): Promise<{ token: string; license: License }> {
    const license = await this.d.licenses.get(licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "trial license not found");
    const now = this.d.clock.now();
    const ended =
      license.status !== "active" ||
      (await this.d.revocations.isRevoked(license.id)) ||
      (license.expiresAt !== null && now > license.expiresAt + license.gracePeriodSeconds);
    if (ended) {
      throw new DomainError(
        "TRIAL_ALREADY_USED",
        "the trial for this product has already been used on this device",
      );
    }
    const issued = await this.d.tokenIssuer.issue(license, {
      deviceBinding: hashDeviceBinding(deviceId),
    });
    return { token: issued.token, license };
  }

  // --- offline activation (air-gapped: signed request/response files) ---

  /**
   * Process an offline activation request file and produce a signed, device-bound
   * response file. Idempotent by requestId (re-submitting returns the same
   * response — no extra seat consumed), which also provides replay protection.
   * The activation code plaintext is used only to look up its hash and is never
   * stored or logged.
   */
  async generateOfflineResponse(request: OfflineRequestFile): Promise<OfflineResponseFile> {
    if (request.kind !== "offline-request" || request.schemaVersion !== OFFLINE_SCHEMA_VERSION) {
      throw new DomainError("VALIDATION", "unsupported offline request file");
    }
    if (!request.requestId || !request.deviceId || !request.activationCode) {
      throw new DomainError("VALIDATION", "offline request is missing required fields");
    }

    // Idempotency / replay: already processed this requestId?
    const prior = await this.d.offline.getResponse(request.requestId);
    if (prior) {
      return this.toResponseFile(prior);
    }

    const hash = this.d.codes.hash(request.activationCode);
    const code = await this.d.activationCodes.findByHash(hash);
    if (!code || code.status === "revoked") {
      throw new DomainError("ACTIVATION_CODE_INVALID", "activation code is invalid");
    }
    const license = await this.d.licenses.get(code.licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");
    if (license.status !== "active") {
      throw new DomainError("LICENSE_NOT_ACTIVE", `license is ${license.status}`);
    }

    const now = this.d.clock.now();

    // Register the device (consume a seat) unless it is already active.
    const existing = await this.d.activations.findActiveByDevice(license.id, request.deviceId);
    if (!existing) {
      // Atomic code consumption first, compensated if the seat insert fails —
      // same race-free pattern as online activate().
      const consumed = await this.d.activationCodes.consumeUse(code.id, now);
      if (!consumed) {
        throw new DomainError("ACTIVATION_CODE_CONSUMED", "activation code exhausted");
      }
      const activation: Activation = {
        id: this.d.ids.next("act"),
        licenseId: license.id,
        activationCodeId: code.id,
        deviceId: request.deviceId,
        deviceLabel: request.deviceLabel ?? null,
        status: "active",
        activatedAt: now,
        lastSeenAt: now,
        deactivatedAt: null,
      };
      const created = await this.d.activations.createIfUnderSeatLimit(
        activation,
        license.maximumSeats,
      );
      if (!created) {
        await this.d.activationCodes.releaseUse(code.id);
        throw new DomainError("SEAT_LIMIT_REACHED", "maximum seats reached");
      }
    }

    // Long-lived, device-bound token so the air-gapped client can run offline
    // for the whole license term (bounded by OFFLINE_TOKEN_MAX_DAYS if perpetual).
    const offlineExpiry =
      license.expiresAt !== null
        ? license.expiresAt
        : now + this.d.offlineTokenMaxDays * 86400;
    const issued = await this.d.tokenIssuer.issue(license, {
      deviceBinding: hashDeviceBinding(request.deviceId),
      expiresAtOverride: offlineExpiry,
      offlineUntilOverride: offlineExpiry,
    });

    const response = {
      requestId: request.requestId,
      licenseId: license.id,
      deviceId: request.deviceId,
      token: issued.token,
      issuedAt: now,
    };
    await this.d.offline.save(
      {
        requestId: request.requestId,
        licenseId: license.id,
        deviceId: request.deviceId,
        createdAt: request.createdAt,
        processedAt: now,
      },
      response,
    );
    await this.d.audit.append({
      id: this.d.ids.next("evt"),
      type: "offline.issued",
      licenseId: license.id,
      actor: `offline:${request.deviceId}`,
      at: now,
      metadata: { requestId: request.requestId },
    });
    return this.toResponseFile(response);
  }

  private toResponseFile(r: {
    requestId: string;
    licenseId: string;
    deviceId: string;
    token: string;
    issuedAt: number;
  }): OfflineResponseFile {
    return {
      schemaVersion: OFFLINE_SCHEMA_VERSION,
      kind: "offline-response",
      requestId: r.requestId,
      licenseId: r.licenseId,
      deviceId: r.deviceId,
      token: r.token,
      issuedAt: r.issuedAt,
    };
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
