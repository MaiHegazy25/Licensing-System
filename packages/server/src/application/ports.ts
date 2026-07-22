/** Ports (interfaces) the application depends on. Adapters live in infrastructure. */
import type { License } from "../domain/license.js";
import type {
  ActivationCodeRecord,
  Activation,
  AuditEvent,
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
}

export interface ActivationRepository {
  create(a: Activation): Promise<void>;
  get(id: string): Promise<Activation | null>;
  countActive(licenseId: string): Promise<number>;
  findActiveByDevice(licenseId: string, deviceId: string): Promise<Activation | null>;
  update(a: Activation): Promise<void>;
  listByLicense(licenseId: string): Promise<Activation[]>;
}

export interface RevocationRepository {
  add(r: Revocation): Promise<void>;
  isRevoked(licenseId: string): Promise<boolean>;
  get(licenseId: string): Promise<Revocation | null>;
}

export interface AuditQuery {
  licenseId?: string;
  limit?: number;
}

export interface AuditRepository {
  append(e: AuditEvent): Promise<void>;
  query(query: AuditQuery): Promise<AuditEvent[]>;
}
