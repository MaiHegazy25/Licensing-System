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
  revocations: RevocationRepository;
  audit: AuditRepository;
  tokenIssuer: TokenIssuer;
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

  async createProduct(input: { key: string; name: string }): Promise<Product> {
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
      actor: "admin",
      at: product.createdAt,
      metadata: { productKey: product.key },
    });
    return product;
  }

  async createLicense(input: CreateLicenseInput): Promise<License> {
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
      actor: "admin",
      at: now,
      metadata: { productId: license.productId, edition: license.edition },
    });
    return license;
  }

  /** Returns the PLAINTEXT activation code exactly once. Only its hash is stored. */
  async generateActivationCode(
    licenseId: string,
    maxActivations = 1,
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
      actor: "admin",
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
      const activeCount = await this.d.activations.countActive(license.id);
      if (activeCount >= license.maximumSeats) {
        throw new DomainError("SEAT_LIMIT_REACHED", "maximum seats reached");
      }
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
      await this.d.activations.create(activation);
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
    revocation: Revocation | null;
    audit: AuditEvent[];
  }> {
    const license = await this.d.licenses.get(licenseId);
    if (!license) throw new DomainError("NOT_FOUND", "license not found");
    const [activations, codes, revocation, audit] = await Promise.all([
      this.d.activations.listByLicense(licenseId),
      this.d.activationCodes.listByLicense(licenseId),
      this.d.revocations.get(licenseId),
      this.d.audit.query({ licenseId, limit: 100 }),
    ]);
    // Strip the hash so the portal never receives code material.
    const activationCodes = codes.map(({ codeHash, ...rest }) => rest);
    return { license, activations, activationCodes, revocation, audit };
  }

  async listAuditEvents(licenseId?: string): Promise<AuditEvent[]> {
    return this.d.audit.query({ licenseId, limit: 200 });
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
