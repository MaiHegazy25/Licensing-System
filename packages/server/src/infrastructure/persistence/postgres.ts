/**
 * Postgres adapters for the repository ports. Row shapes match
 * migrations/001_init.sql. BIGINT epoch columns come back as strings from
 * node-pg, so they are converted to numbers on read.
 *
 * Seat enforcement (`createIfUnderSeatLimit`) locks the license row with
 * SELECT ... FOR UPDATE so concurrent activations for the same license
 * serialize — the count-then-insert is atomic and can never oversell.
 */
import { DomainError } from "../../domain/errors.js";
import type { License } from "../../domain/license.js";
import type {
  Activation,
  ActivationCodeRecord,
  AuditEvent,
  Product,
  Revocation,
} from "../../domain/types.js";
import type {
  ActivationCodeRepository,
  ActivationRepository,
  AuditQuery,
  AuditRepository,
  LicenseQuery,
  LicenseRepository,
  ProductRepository,
  RevocationRepository,
} from "../../application/ports.js";
import type { Pool } from "./pool.js";
import { withTransaction } from "./pool.js";

const UNIQUE_VIOLATION = "23505";

function toLicense(r: Record<string, unknown>): License {
  return {
    id: r.id as string,
    customerId: r.customer_id as string,
    organizationId: (r.organization_id as string | null) ?? null,
    productId: r.product_id as string,
    edition: r.edition as string,
    enabledFeatures: (r.enabled_features as string[]) ?? [],
    licenseType: r.license_type as License["licenseType"],
    status: r.status as License["status"],
    maximumSeats: Number(r.maximum_seats),
    notBefore: Number(r.not_before),
    expiresAt: r.expires_at == null ? null : Number(r.expires_at),
    maintenanceExpiresAt: r.maintenance_expires_at == null ? null : Number(r.maintenance_expires_at),
    gracePeriodSeconds: Number(r.grace_period_seconds),
    offlineUntil: r.offline_until == null ? null : Number(r.offline_until),
    createdAt: Number(r.created_at),
    updatedAt: Number(r.updated_at),
    version: Number(r.version),
  };
}

function toActivation(r: Record<string, unknown>): Activation {
  return {
    id: r.id as string,
    licenseId: r.license_id as string,
    activationCodeId: r.activation_code_id as string,
    deviceId: r.device_id as string,
    deviceLabel: (r.device_label as string | null) ?? null,
    status: r.status as Activation["status"],
    activatedAt: Number(r.activated_at),
    lastSeenAt: Number(r.last_seen_at),
    deactivatedAt: r.deactivated_at == null ? null : Number(r.deactivated_at),
  };
}

function toCode(r: Record<string, unknown>): ActivationCodeRecord {
  return {
    id: r.id as string,
    licenseId: r.license_id as string,
    codeHash: r.code_hash as string,
    status: r.status as ActivationCodeRecord["status"],
    maxActivations: Number(r.max_activations),
    usedActivations: Number(r.used_activations),
    createdAt: Number(r.created_at),
    consumedAt: r.consumed_at == null ? null : Number(r.consumed_at),
  };
}

export class PgProductRepository implements ProductRepository {
  constructor(private readonly pool: Pool) {}
  async create(p: Product): Promise<void> {
    await this.pool.query(
      "INSERT INTO products (id, key, name, created_at) VALUES ($1,$2,$3,$4)",
      [p.id, p.key, p.name, p.createdAt],
    );
  }
  async get(id: string): Promise<Product | null> {
    const { rows } = await this.pool.query("SELECT * FROM products WHERE id=$1", [id]);
    return rows[0] ? this.map(rows[0]) : null;
  }
  async getByKey(key: string): Promise<Product | null> {
    const { rows } = await this.pool.query("SELECT * FROM products WHERE key=$1", [key]);
    return rows[0] ? this.map(rows[0]) : null;
  }
  async list(): Promise<Product[]> {
    const { rows } = await this.pool.query("SELECT * FROM products ORDER BY created_at DESC");
    return rows.map((r) => this.map(r));
  }
  private map(r: Record<string, unknown>): Product {
    return { id: r.id as string, key: r.key as string, name: r.name as string, createdAt: Number(r.created_at) };
  }
}

export class PgLicenseRepository implements LicenseRepository {
  constructor(private readonly pool: Pool) {}
  async create(l: License): Promise<void> {
    await this.pool.query(
      `INSERT INTO licenses
        (id, customer_id, organization_id, product_id, edition, enabled_features,
         license_type, status, maximum_seats, not_before, expires_at,
         maintenance_expires_at, grace_period_seconds, offline_until,
         created_at, updated_at, version)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
      [
        l.id, l.customerId, l.organizationId, l.productId, l.edition,
        JSON.stringify(l.enabledFeatures), l.licenseType, l.status, l.maximumSeats,
        l.notBefore, l.expiresAt, l.maintenanceExpiresAt, l.gracePeriodSeconds,
        l.offlineUntil, l.createdAt, l.updatedAt, l.version,
      ],
    );
  }
  async get(id: string): Promise<License | null> {
    const { rows } = await this.pool.query("SELECT * FROM licenses WHERE id=$1", [id]);
    return rows[0] ? toLicense(rows[0]) : null;
  }
  async update(l: License, expectedVersion: number): Promise<void> {
    const { rowCount } = await this.pool.query(
      `UPDATE licenses SET
         customer_id=$2, organization_id=$3, edition=$4, enabled_features=$5::jsonb,
         license_type=$6, status=$7, maximum_seats=$8, not_before=$9, expires_at=$10,
         maintenance_expires_at=$11, grace_period_seconds=$12, offline_until=$13,
         updated_at=$14, version=$15
       WHERE id=$1 AND version=$16`,
      [
        l.id, l.customerId, l.organizationId, l.edition, JSON.stringify(l.enabledFeatures),
        l.licenseType, l.status, l.maximumSeats, l.notBefore, l.expiresAt,
        l.maintenanceExpiresAt, l.gracePeriodSeconds, l.offlineUntil, l.updatedAt,
        l.version, expectedVersion,
      ],
    );
    if (rowCount === 0) {
      throw new DomainError("VALIDATION", "concurrent modification (version mismatch)");
    }
  }
  async list(query: LicenseQuery): Promise<{ items: License[]; total: number }> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (query.customerId) { params.push(query.customerId); where.push(`customer_id=$${params.length}`); }
    if (query.productId) { params.push(query.productId); where.push(`product_id=$${params.length}`); }
    if (query.status) { params.push(query.status); where.push(`status=$${params.length}`); }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const totalRes = await this.pool.query<{ n: string }>(
      `SELECT count(*)::int AS n FROM licenses ${whereSql}`,
      params,
    );
    const total = Number(totalRes.rows[0]?.n ?? 0);

    const limit = query.limit ?? 50;
    const offset = query.offset ?? 0;
    const { rows } = await this.pool.query(
      `SELECT * FROM licenses ${whereSql} ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset],
    );
    return { items: rows.map(toLicense), total };
  }
}

export class PgActivationCodeRepository implements ActivationCodeRepository {
  constructor(private readonly pool: Pool) {}
  async create(r: ActivationCodeRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO activation_codes
        (id, license_id, code_hash, status, max_activations, used_activations, created_at, consumed_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [r.id, r.licenseId, r.codeHash, r.status, r.maxActivations, r.usedActivations, r.createdAt, r.consumedAt],
    );
  }
  async get(id: string): Promise<ActivationCodeRecord | null> {
    const { rows } = await this.pool.query("SELECT * FROM activation_codes WHERE id=$1", [id]);
    return rows[0] ? toCode(rows[0]) : null;
  }
  async findByHash(hash: string): Promise<ActivationCodeRecord | null> {
    const { rows } = await this.pool.query("SELECT * FROM activation_codes WHERE code_hash=$1", [hash]);
    return rows[0] ? toCode(rows[0]) : null;
  }
  async update(r: ActivationCodeRecord): Promise<void> {
    await this.pool.query(
      `UPDATE activation_codes SET status=$2, max_activations=$3, used_activations=$4, consumed_at=$5 WHERE id=$1`,
      [r.id, r.status, r.maxActivations, r.usedActivations, r.consumedAt],
    );
  }
  async listByLicense(licenseId: string): Promise<ActivationCodeRecord[]> {
    const { rows } = await this.pool.query(
      "SELECT * FROM activation_codes WHERE license_id=$1 ORDER BY created_at DESC",
      [licenseId],
    );
    return rows.map(toCode);
  }
}

export class PgActivationRepository implements ActivationRepository {
  constructor(private readonly pool: Pool) {}
  async create(a: Activation): Promise<void> {
    await this.pool.query(
      `INSERT INTO activations
        (id, license_id, activation_code_id, device_id, device_label, status, activated_at, last_seen_at, deactivated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [a.id, a.licenseId, a.activationCodeId, a.deviceId, a.deviceLabel, a.status, a.activatedAt, a.lastSeenAt, a.deactivatedAt],
    );
  }
  async get(id: string): Promise<Activation | null> {
    const { rows } = await this.pool.query("SELECT * FROM activations WHERE id=$1", [id]);
    return rows[0] ? toActivation(rows[0]) : null;
  }
  async countActive(licenseId: string): Promise<number> {
    const { rows } = await this.pool.query<{ n: string }>(
      "SELECT count(*)::int AS n FROM activations WHERE license_id=$1 AND status='active'",
      [licenseId],
    );
    return Number(rows[0]?.n ?? 0);
  }
  async findActiveByDevice(licenseId: string, deviceId: string): Promise<Activation | null> {
    const { rows } = await this.pool.query(
      "SELECT * FROM activations WHERE license_id=$1 AND device_id=$2 AND status='active'",
      [licenseId, deviceId],
    );
    return rows[0] ? toActivation(rows[0]) : null;
  }
  async update(a: Activation): Promise<void> {
    await this.pool.query(
      `UPDATE activations SET device_label=$2, status=$3, last_seen_at=$4, deactivated_at=$5 WHERE id=$1`,
      [a.id, a.deviceLabel, a.status, a.lastSeenAt, a.deactivatedAt],
    );
  }
  async listByLicense(licenseId: string): Promise<Activation[]> {
    const { rows } = await this.pool.query(
      "SELECT * FROM activations WHERE license_id=$1 ORDER BY activated_at DESC",
      [licenseId],
    );
    return rows.map(toActivation);
  }
  async createIfUnderSeatLimit(a: Activation, maxSeats: number): Promise<boolean> {
    return withTransaction(this.pool, async (client) => {
      // Serialize seat operations for THIS license: the row lock blocks other
      // concurrent activations until we commit, so count+insert is atomic.
      await client.query("SELECT 1 FROM licenses WHERE id=$1 FOR UPDATE", [a.licenseId]);
      const { rows } = await client.query<{ n: string }>(
        "SELECT count(*)::int AS n FROM activations WHERE license_id=$1 AND status='active'",
        [a.licenseId],
      );
      if (Number(rows[0]?.n ?? 0) >= maxSeats) return false;
      try {
        await client.query(
          `INSERT INTO activations
            (id, license_id, activation_code_id, device_id, device_label, status, activated_at, last_seen_at, deactivated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [a.id, a.licenseId, a.activationCodeId, a.deviceId, a.deviceLabel, a.status, a.activatedAt, a.lastSeenAt, a.deactivatedAt],
        );
        return true;
      } catch (e) {
        // Another concurrent activation already registered this exact device:
        // the partial unique index fires. Treat as success (device is active).
        if ((e as { code?: string }).code === UNIQUE_VIOLATION) return true;
        throw e;
      }
    });
  }
}

export class PgRevocationRepository implements RevocationRepository {
  constructor(private readonly pool: Pool) {}
  async add(r: Revocation): Promise<void> {
    await this.pool.query(
      `INSERT INTO revocations (license_id, reason, revoked_at) VALUES ($1,$2,$3)
       ON CONFLICT (license_id) DO UPDATE SET reason=EXCLUDED.reason, revoked_at=EXCLUDED.revoked_at`,
      [r.licenseId, r.reason, r.revokedAt],
    );
  }
  async isRevoked(licenseId: string): Promise<boolean> {
    const { rowCount } = await this.pool.query("SELECT 1 FROM revocations WHERE license_id=$1", [licenseId]);
    return (rowCount ?? 0) > 0;
  }
  async get(licenseId: string): Promise<Revocation | null> {
    const { rows } = await this.pool.query("SELECT * FROM revocations WHERE license_id=$1", [licenseId]);
    const r = rows[0];
    return r ? { licenseId: r.license_id, reason: r.reason, revokedAt: Number(r.revoked_at) } : null;
  }
}

export class PgAuditRepository implements AuditRepository {
  constructor(private readonly pool: Pool) {}
  async append(e: AuditEvent): Promise<void> {
    await this.pool.query(
      "INSERT INTO audit_events (id, type, license_id, actor, at, metadata) VALUES ($1,$2,$3,$4,$5,$6::jsonb)",
      [e.id, e.type, e.licenseId, e.actor, e.at, JSON.stringify(e.metadata)],
    );
  }
  async query(query: AuditQuery): Promise<AuditEvent[]> {
    const params: unknown[] = [];
    let where = "";
    if (query.licenseId) { params.push(query.licenseId); where = `WHERE license_id=$${params.length}`; }
    params.push(query.limit ?? 100);
    const { rows } = await this.pool.query(
      `SELECT * FROM audit_events ${where} ORDER BY at DESC LIMIT $${params.length}`,
      params,
    );
    return rows.map((r) => ({
      id: r.id,
      type: r.type,
      licenseId: r.license_id,
      actor: r.actor,
      at: Number(r.at),
      metadata: r.metadata ?? {},
    }));
  }
}
