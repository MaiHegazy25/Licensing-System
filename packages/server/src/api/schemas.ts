/**
 * JSON Schemas for request bodies.
 *
 * `req.body as X` is a compile-time fiction — at runtime the body is whatever
 * the caller sent. Fastify validates against these schemas before the handler
 * runs and rejects mismatches with 400 (mapped to the VALIDATION error code),
 * so handlers can trust the shape they assert.
 *
 * Bounds are deliberate: they cap memory/DB write size and keep hostile input
 * (huge arrays, megabyte strings) from reaching the domain layer.
 */
import { ROLES } from "../domain/rbac.js";

const LICENSE_TYPES = [
  "named_user",
  "device",
  "floating",
  "subscription",
  "perpetual",
  "trial",
] as const;

/** Epoch SECONDS (never milliseconds) — see the time convention in CLAUDE.md. */
const epoch = { type: "integer", minimum: 0, maximum: 4_102_444_800 } as const;
const nullableEpoch = { type: ["integer", "null"], minimum: 0, maximum: 4_102_444_800 } as const;

const str = (maxLength: number) => ({ type: "string", minLength: 1, maxLength }) as const;
const nullableStr = (maxLength: number) => ({ type: ["string", "null"], maxLength }) as const;

const deviceId = str(256);
/** Compact JWS — generous ceiling, still bounded. */
const licenseToken = str(8192);

export const S = {
  createProduct: {
    type: "object",
    required: ["key", "name"],
    properties: {
      key: { type: "string", minLength: 1, maxLength: 100, pattern: "^[A-Za-z0-9._-]+$" },
      name: str(200),
      trial: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          days: { type: "integer", minimum: 1, maximum: 365 },
          edition: str(100),
          features: { type: "array", maxItems: 200, items: str(100) },
        },
      },
    },
  },

  createLicense: {
    type: "object",
    required: ["customerId", "productId", "edition", "enabledFeatures", "licenseType", "maximumSeats"],
    properties: {
      customerId: str(200),
      organizationId: nullableStr(200),
      productId: str(200),
      edition: str(100),
      enabledFeatures: { type: "array", maxItems: 500, items: str(100) },
      licenseType: { type: "string", enum: [...LICENSE_TYPES] },
      maximumSeats: { type: "integer", minimum: 1, maximum: 1_000_000 },
      notBefore: epoch,
      expiresAt: nullableEpoch,
      maintenanceExpiresAt: nullableEpoch,
      gracePeriodSeconds: { type: "integer", minimum: 0, maximum: 31_536_000 },
      offlineUntil: nullableEpoch,
    },
  },

  generateActivationCode: {
    type: "object",
    properties: { maxActivations: { type: "integer", minimum: 1, maximum: 10_000 } },
  },

  reason: {
    type: "object",
    properties: { reason: { type: "string", maxLength: 500 } },
  },

  renew: {
    type: "object",
    required: ["expiresAt"],
    properties: { expiresAt: nullableEpoch, maintenanceExpiresAt: nullableEpoch },
  },

  activate: {
    type: "object",
    required: ["activationCode", "deviceId"],
    properties: {
      activationCode: str(200),
      deviceId,
      deviceLabel: nullableStr(200),
    },
  },

  /** Proof-of-possession: licenseId comes from the verified token, not the body. */
  validate: {
    type: "object",
    required: ["token", "deviceId"],
    properties: { token: licenseToken, deviceId },
  },

  deactivate: {
    type: "object",
    required: ["token", "deviceId"],
    properties: { token: licenseToken, deviceId },
  },

  trialStart: {
    type: "object",
    required: ["productKey", "deviceId"],
    properties: { productKey: str(100), deviceId, deviceLabel: nullableStr(200) },
  },

  floatingCheckout: {
    type: "object",
    required: ["licenseId", "deviceId"],
    properties: { licenseId: str(200), deviceId, deviceLabel: nullableStr(200) },
  },

  floatingLease: {
    type: "object",
    required: ["leaseId", "deviceId"],
    properties: { leaseId: str(200), deviceId },
  },

  offlineRequest: {
    type: "object",
    required: ["schemaVersion", "kind", "requestId", "deviceId", "activationCode"],
    properties: {
      schemaVersion: { type: "integer", minimum: 1, maximum: 100 },
      kind: { type: "string", enum: ["offline-request"] },
      requestId: str(200),
      deviceId,
      deviceLabel: nullableStr(200),
      activationCode: str(200),
      createdAt: epoch,
    },
  },

  activationReset: {
    type: "object",
    properties: { note: { type: "string", maxLength: 500 } },
  },
} as const;

/** Exported for tests/tooling that assert the role vocabulary stays in sync. */
export const KNOWN_ROLES = ROLES;
