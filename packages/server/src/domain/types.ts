import type { LicenseType } from "@vehiclevo/licensing-shared";

export interface Product {
  id: string;
  key: string; // stable human code, e.g. "vv-analyzer"
  name: string;
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
  activationCodeId: string;
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

export type AuditEventType =
  | "product.created"
  | "license.created"
  | "activation_code.generated"
  | "license.activated"
  | "license.validated"
  | "license.revoked"
  | "license.suspended"
  | "license.resumed"
  | "license.renewed";

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
