import type { LicenseType } from "@vehiclevo/licensing-shared";

/** Per-product self-service trial policy. */
export interface TrialPolicy {
  enabled: boolean;
  days: number;
  edition: string;
  features: string[];
}

export const DEFAULT_TRIAL_POLICY: TrialPolicy = {
  enabled: false,
  days: 14,
  edition: "trial",
  features: [],
};

export interface Product {
  id: string;
  key: string; // stable human code, e.g. "vv-analyzer"
  name: string;
  createdAt: number;
  trial: TrialPolicy;
}

/** One row per (product, device) trial grant — the one-trial-per-device guard. */
export interface TrialRecord {
  id: string;
  productId: string;
  licenseId: string;
  deviceId: string;
  createdAt: number;
}

export interface Edition {
  productId: string;
  code: string; // "standard" | "pro" | "enterprise"
  features: string[];
}

/** Only the hash of the activation code is stored — never the plaintext. */
export interface ActivationCodeRecord {
  id: string;
  licenseId: string;
  codeHash: string;
  status: "unused" | "consumed" | "revoked";
  maxActivations: number;
  usedActivations: number;
  createdAt: number;
  consumedAt: number | null;
}

/** A device that consumed an activation code — the runtime seat holder. */
export interface Activation {
  id: string;
  licenseId: string;
  /** null for trial activations (issued without an activation code). */
  activationCodeId: string | null;
  deviceId: string; // salted, derived — NOT a raw MAC/serial
  deviceLabel: string | null;
  status: "active" | "deactivated";
  activatedAt: number;
  lastSeenAt: number;
  deactivatedAt: number | null;
}

export interface Revocation {
  licenseId: string;
  reason: string;
  revokedAt: number;
}

/**
 * A concurrent (floating) seat lease. A lease is "active" while
 * releasedAt IS NULL AND expiresAt > now. A crashed client's lease is reclaimed
 * automatically once it expires (no explicit return needed).
 */
export interface FloatingLease {
  id: string;
  licenseId: string;
  deviceId: string;
  deviceLabel: string | null;
  acquiredAt: number;
  expiresAt: number;
  releasedAt: number | null;
}

/** Persisted offline activation request (never stores the plaintext code). */
export interface OfflineRequestRecord {
  requestId: string;
  licenseId: string;
  deviceId: string;
  createdAt: number;
  processedAt: number;
}

export interface OfflineResponseRecord {
  requestId: string;
  licenseId: string;
  deviceId: string;
  token: string;
  issuedAt: number;
}

export type AuditEventType =
  | "product.created"
  | "license.created"
  | "activation_code.generated"
  | "license.activated"
  | "license.validated"
  | "license.revoked"
  | "license.suspended"
  | "license.resumed"
  | "license.renewed"
  | "device.deactivated"
  | "activation_reset.requested"
  | "license_file.downloaded"
  | "floating.checkout"
  | "floating.return"
  | "offline.issued"
  | "trial.started";

export interface AuditEvent {
  id: string;
  type: AuditEventType;
  licenseId: string | null;
  actor: string; // admin subject id or "sdk:<deviceId>"
  at: number;
  /** Non-sensitive metadata only. Never activation codes / tokens / secrets. */
  metadata: Record<string, string | number | boolean | null>;
}

export type { LicenseType };
