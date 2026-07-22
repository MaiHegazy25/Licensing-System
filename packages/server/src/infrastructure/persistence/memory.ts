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
  FloatingLease,
  OfflineRequestRecord,
  OfflineResponseRecord,
  Product,
  Revocation,
} from "../../domain/types.js";
import type {
  AcquireLeaseParams,
  ActivationCodeRepository,
  ActivationRepository,
  AuditQuery,
  AuditRepository,
  FloatingLeaseRepository,
  LicenseQuery,
  LicenseRepository,
  OfflineRepository,
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
  async createIfUnderSeatLimit(a: Activation, maxSeats: number): Promise<boolean> {
    // Single-threaded event loop: this check-then-insert is already atomic.
    let active = 0;
    for (const x of this.byId.values()) {
      if (x.licenseId === a.licenseId && x.status === "active") active++;
    }
    if (active >= maxSeats) return false;
    this.byId.set(a.id, clone(a));
    return true;
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

export class InMemoryFloatingLeaseRepository implements FloatingLeaseRepository {
  private byId = new Map<string, FloatingLease>();

  private isActive(l: FloatingLease, now: number): boolean {
    return l.releasedAt === null && l.expiresAt > now;
  }

  async acquire(p: AcquireLeaseParams): Promise<FloatingLease | null> {
    // Single-threaded: reuse-or-count-or-insert is atomic here.
    for (const l of this.byId.values()) {
      if (l.licenseId === p.licenseId && l.deviceId === p.deviceId && this.isActive(l, p.now)) {
        l.expiresAt = p.now + p.ttlSeconds; // renew existing device lease
        return clone(l);
      }
    }
    let active = 0;
    for (const l of this.byId.values()) {
      if (l.licenseId === p.licenseId && this.isActive(l, p.now)) active++;
    }
    if (active >= p.maxSeats) return null;
    const lease: FloatingLease = {
      id: p.id,
      licenseId: p.licenseId,
      deviceId: p.deviceId,
      deviceLabel: p.deviceLabel,
      acquiredAt: p.now,
      expiresAt: p.now + p.ttlSeconds,
      releasedAt: null,
    };
    this.byId.set(lease.id, clone(lease));
    return clone(lease);
  }

  async heartbeat(p: {
    leaseId: string;
    deviceId: string;
    now: number;
    ttlSeconds: number;
  }): Promise<FloatingLease | null> {
    const l = this.byId.get(p.leaseId);
    if (!l || l.deviceId !== p.deviceId || !this.isActive(l, p.now)) return null;
    l.expiresAt = p.now + p.ttlSeconds;
    return clone(l);
  }

  async release(leaseId: string, deviceId: string, now: number): Promise<boolean> {
    const l = this.byId.get(leaseId);
    if (!l || l.deviceId !== deviceId || l.releasedAt !== null) return false;
    l.releasedAt = now;
    return true;
  }

  async countActive(licenseId: string, now: number): Promise<number> {
    let n = 0;
    for (const l of this.byId.values()) {
      if (l.licenseId === licenseId && this.isActive(l, now)) n++;
    }
    return n;
  }

  async listActive(licenseId: string, now: number): Promise<FloatingLease[]> {
    return [...this.byId.values()]
      .filter((l) => l.licenseId === licenseId && this.isActive(l, now))
      .sort((a, b) => a.acquiredAt - b.acquiredAt)
      .map(clone);
  }
}

export class InMemoryOfflineRepository implements OfflineRepository {
  private responses = new Map<string, OfflineResponseRecord>();
  private requests = new Map<string, OfflineRequestRecord>();
  async getResponse(requestId: string): Promise<OfflineResponseRecord | null> {
    return this.responses.has(requestId) ? clone(this.responses.get(requestId)!) : null;
  }
  async save(request: OfflineRequestRecord, response: OfflineResponseRecord): Promise<void> {
    this.requests.set(request.requestId, clone(request));
    this.responses.set(response.requestId, clone(response));
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
