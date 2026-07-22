/**
 * License aggregate + lifecycle state machine.
 *
 * The status here is SERVER-SIDE MUTABLE STATE — deliberately separate from the
 * signed token's immutable claims. Revocation/suspension live here and are the
 * reason online validation exists.
 */
import { DomainError } from "./errors.js";
import type { LicenseType } from "@vehiclevo/licensing-shared";

export type LicenseStatus =
  | "draft" // created, not yet issuable
  | "active" // normal operating state
  | "suspended" // temporarily disabled (billing hold, dispute)
  | "expired" // past expiry
  | "revoked"; // permanently killed (terminal)

/** Allowed transitions. Terminal states have no outgoing edges. */
const TRANSITIONS: Record<LicenseStatus, LicenseStatus[]> = {
  draft: ["active", "revoked"],
  active: ["suspended", "expired", "revoked"],
  suspended: ["active", "expired", "revoked"],
  expired: ["active", "revoked"], // renewal can reactivate
  revoked: [], // terminal
};

export function canTransition(from: LicenseStatus, to: LicenseStatus): boolean {
  return TRANSITIONS[from].includes(to);
}

export function assertTransition(from: LicenseStatus, to: LicenseStatus): void {
  if (!canTransition(from, to)) {
    throw new DomainError(
      "INVALID_STATE_TRANSITION",
      `cannot transition license from '${from}' to '${to}'`,
    );
  }
}

export interface License {
  id: string;
  customerId: string;
  organizationId: string | null;
  productId: string;
  edition: string;
  enabledFeatures: string[];
  licenseType: LicenseType;
  status: LicenseStatus;
  maximumSeats: number;
  notBefore: number; // epoch seconds
  expiresAt: number | null;
  maintenanceExpiresAt: number | null;
  gracePeriodSeconds: number;
  offlineUntil: number | null;
  createdAt: number;
  updatedAt: number;
  /** Optimistic-concurrency version. */
  version: number;
}
