/** Ports (interfaces) the application depends on. Adapters live in infrastructure. */
import type { License } from "../domain/license.js";
import type {
  ActivationCodeRecord,
  Activation,
  AuditEvent,
  FloatingLease,
  OfflineRequestRecord,
  OfflineResponseRecord,
  Product,
  Revocation,
} from "../domain/types.js";

export interface Clock {
  now(): number; // epoch seconds
}

export interface IdGenerator {
  next(prefix: string): string;
}

/**
 * Generates and verifies activation codes. Plaintext is returned exactly once
 * at generation time; only the hash is ever persisted.
 */
export interface ActivationCodeService {
  generate(): { plaintext: string; hash: string };
  hash(plaintext: string): string;
  verify(plaintext: string, hash: string): boolean;
}

export interface ProductRepository {
  create(p: Product): Promise<void>;
  get(id: string): Promise<Product | null>;
  getByKey(key: string): Promise<Product | null>;
  list(): Promise<Product[]>;
}

export interface LicenseQuery {
  customerId?: string;
  productId?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export interface LicenseRepository {
  create(l: License): Promise<void>;
  get(id: string): Promise<License | null>;
  /** Persist with optimistic concurrency; throws on version mismatch. */
  update(l: License, expectedVersion: number): Promise<void>;
  list(query: LicenseQuery): Promise<{ items: License[]; total: number }>;
}

export interface ActivationCodeRepository {
  create(r: ActivationCodeRecord): Promise<void>;
  get(id: string): Promise<ActivationCodeRecord | null>;
  findByHash(hash: string): Promise<ActivationCodeRecord | null>;
  update(r: ActivationCodeRecord): Promise<void>;
  listByLicense(licenseId: string): Promise<ActivationCodeRecord[]>;
  /**
   * Atomically consume one use of the code. Returns false if the code is
   * revoked or already at maxActivations. MUST be race-free under concurrency
   * (conditional UPDATE in Postgres) so a code can never be over-consumed.
   */
  consumeUse(id: string, now: number): Promise<boolean>;
  /** Compensating action when a consume was granted but the activation failed. */
  releaseUse(id: string): Promise<void>;
}

export interface ActivationRepository {
  create(a: Activation): Promise<void>;
  get(id: string): Promise<Activation | null>;
  countActive(licenseId: string): Promise<number>;
  findActiveByDevice(licenseId: string, deviceId: string): Promise<Activation | null>;
  update(a: Activation): Promise<void>;
  listByLicense(licenseId: string): Promise<Activation[]>;
  /**
   * Atomically create the activation ONLY if the license's active-seat count is
   * below `maxSeats`. Returns true if created, false if the seat cap would be
   * exceeded. Must be race-free under concurrency (SQL conditional insert /
   * row lock in Postgres) so the system never issues more seats than allowed.
   */
  createIfUnderSeatLimit(a: Activation, maxSeats: number): Promise<boolean>;
}

export interface RevocationRepository {
  add(r: Revocation): Promise<void>;
  isRevoked(licenseId: string): Promise<boolean>;
  get(licenseId: string): Promise<Revocation | null>;
}

export interface AcquireLeaseParams {
  id: string;
  licenseId: string;
  deviceId: string;
  deviceLabel: string | null;
  now: number;
  ttlSeconds: number;
  maxSeats: number;
}

export interface FloatingLeaseRepository {
  /**
   * Atomically acquire (or renew, if this device already holds one) a concurrent
   * seat. Returns the granted lease, or null if the license is already at its
   * concurrent-seat cap. MUST be race-free under concurrency so the cap is never
   * exceeded (Postgres uses a license row lock).
   */
  acquire(params: AcquireLeaseParams): Promise<FloatingLease | null>;
  /** Extend an active lease; returns the updated lease, or null if it is no longer active. */
  heartbeat(params: {
    leaseId: string;
    deviceId: string;
    now: number;
    ttlSeconds: number;
  }): Promise<FloatingLease | null>;
  /** Release a lease; returns true if it was active. Idempotent. */
  release(leaseId: string, deviceId: string, now: number): Promise<boolean>;
  countActive(licenseId: string, now: number): Promise<number>;
  listActive(licenseId: string, now: number): Promise<FloatingLease[]>;
}

export interface OfflineRepository {
  /** Returns the already-issued response for a requestId (idempotency/replay). */
  getResponse(requestId: string): Promise<OfflineResponseRecord | null>;
  /** Persist the request + its issued response together. */
  save(request: OfflineRequestRecord, response: OfflineResponseRecord): Promise<void>;
}

export interface AuditQuery {
  licenseId?: string;
  limit?: number;
}

export interface AuditRepository {
  append(e: AuditEvent): Promise<void>;
  query(query: AuditQuery): Promise<AuditEvent[]>;
}

/** Security telemetry (rate-limit hits, failed auth, replay attempts, ...). */
export interface SecurityEvent {
  id: string;
  type: string; // e.g. "rate_limit_exceeded" | "auth_failed"
  /** Who/where it came from (IP, device id) — never a secret. */
  subject: string | null;
  at: number;
  metadata: Record<string, string | number | boolean | null>;
}

export interface SecurityEventRepository {
  record(e: SecurityEvent): Promise<void>;
}
