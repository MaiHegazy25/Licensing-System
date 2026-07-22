/**
 * In-memory adapters. Used by the demo and the deterministic test suite; the
 * Postgres adapters (see migrations/ + postgres.ts) are the production path.
 * Kept behaviourally faithful: optimistic-concurrency + seat counting included.
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

const clone = <T>(v: T): T => structuredClone(v);

export class InMemoryProductRepository implements ProductRepository {
  private byId = new Map<string, Product>();
  private byKey = new Map<string, Product>();
  async create(p: Product): Promise<void> {
    this.byId.set(p.id, clone(p));
    this.byKey.set(p.key, clone(p));
  }
  async get(id: string): Promise<Product | null> {
    return this.byId.has(id) ? clone(this.byId.get(id)!) : null;
  }
  async getByKey(key: string): Promise<Product | null> {
    return this.byKey.has(key) ? clone(this.byKey.get(key)!) : null;
  }
  async list(): Promise<Product[]> {
    return [...this.byId.values()]
      .sort((a, b) => b.createdAt - a.createdAt)
      .map(clone);
  }
}

export class InMemoryLicenseRepository implements LicenseRepository {
  private byId = new Map<string, License>();
  async create(l: License): Promise<void> {
    this.byId.set(l.id, clone(l));
  }
  async get(id: string): Promise<License | null> {
    return this.byId.has(id) ? clone(this.byId.get(id)!) : null;
  }
  async update(l: License, expectedVersion: number): Promise<void> {
    const current = this.byId.get(l.id);
    if (!current) throw new DomainError("NOT_FOUND", "license not found");
    if (current.version !== expectedVersion) {
      throw new DomainError("VALIDATION", "concurrent modification (version mismatch)");
    }
    this.byId.set(l.id, clone(l));
  }
  async list(query: LicenseQuery): Promise<{ items: License[]; total: number }> {
    let items = [...this.byId.values()].sort((a, b) => b.createdAt - a.createdAt);
    if (query.customerId) items = items.filter((l) => l.customerId === query.customerId);
    if (query.productId) items = items.filter((l) => l.productId === query.productId);
    if (query.status) items = items.filter((l) => l.status === query.status);
    const total = items.length;
    const offset = query.offset ?? 0;
    const limit = query.limit ?? 50;
    return { items: items.slice(offset, offset + limit).map(clone), total };
  }
}

export class InMemoryActivationCodeRepository implements ActivationCodeRepository {
  private byId = new Map<string, ActivationCodeRecord>();
  private byHash = new Map<string, string>();
  async create(r: ActivationCodeRecord): Promise<void> {
    this.byId.set(r.id, clone(r));
    this.byHash.set(r.codeHash, r.id);
  }
  async get(id: string): Promise<ActivationCodeRecord | null> {
    return this.byId.has(id) ? clone(this.byId.get(id)!) : null;
  }
  async findByHash(hash: string): Promise<ActivationCodeRecord | null> {
    const id = this.byHash.get(hash);
    return id ? clone(this.byId.get(id)!) : null;
  }
  async update(r: ActivationCodeRecord): Promise<void> {
    this.byId.set(r.id, clone(r));
  }
  async listByLicense(licenseId: string): Promise<ActivationCodeRecord[]> {
    return [...this.byId.values()]
      .filter((r) => r.licenseId === licenseId)
      .sort((a, b) => b.createdAt - a.createdAt)
      .map(clone);
  }
}

export class InMemoryActivationRepository implements ActivationRepository {
  private byId = new Map<string, Activation>();
  async create(a: Activation): Promise<void> {
    this.byId.set(a.id, clone(a));
  }
  async get(id: string): Promise<Activation | null> {
    return this.byId.has(id) ? clone(this.byId.get(id)!) : null;
  }
  async countActive(licenseId: string): Promise<number> {
    let n = 0;
    for (const a of this.byId.values()) {
      if (a.licenseId === licenseId && a.status === "active") n++;
    }
    return n;
  }
  async findActiveByDevice(
    licenseId: string,
    deviceId: string,
  ): Promise<Activation | null> {
    for (const a of this.byId.values()) {
      if (a.licenseId === licenseId && a.deviceId === deviceId && a.status === "active") {
        return clone(a);
      }
    }
    return null;
  }
  async update(a: Activation): Promise<void> {
    this.byId.set(a.id, clone(a));
  }
  async listByLicense(licenseId: string): Promise<Activation[]> {
    return [...this.byId.values()]
      .filter((a) => a.licenseId === licenseId)
      .sort((a, b) => b.activatedAt - a.activatedAt)
      .map(clone);
  }
}

export class InMemoryRevocationRepository implements RevocationRepository {
  private revoked = new Map<string, Revocation>();
  async add(r: Revocation): Promise<void> {
    this.revoked.set(r.licenseId, clone(r));
  }
  async isRevoked(licenseId: string): Promise<boolean> {
    return this.revoked.has(licenseId);
  }
  async get(licenseId: string): Promise<Revocation | null> {
    return this.revoked.has(licenseId) ? clone(this.revoked.get(licenseId)!) : null;
  }
}

export class InMemoryAuditRepository implements AuditRepository {
  readonly events: AuditEvent[] = [];
  async append(e: AuditEvent): Promise<void> {
    this.events.push(clone(e));
  }
  async query(query: AuditQuery): Promise<AuditEvent[]> {
    let items = [...this.events].sort((a, b) => b.at - a.at);
    if (query.licenseId) items = items.filter((e) => e.licenseId === query.licenseId);
    return items.slice(0, query.limit ?? 100).map(clone);
  }
}
