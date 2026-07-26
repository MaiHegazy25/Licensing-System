/**
 * HTTP API (Fastify). Thin transport layer over the LicensingService.
 *
 * AuthN/Z: every admin route authenticates the bearer token to a Principal
 * (subject + role) via the PrincipalResolver, then authorizes a specific
 * Permission against the role. The API-key resolver is the dev/slice adapter;
 * PRODUCTION swaps in an OIDC-token resolver behind the same port — routes and
 * the permission matrix are unchanged.
 */
import { randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import {
  hashDeviceBinding,
  verifyLicenseToken,
  type OfflineRequestFile,
} from "@vehiclevo/licensing-shared";
import { DomainError, type DomainErrorCode } from "../domain/errors.js";
import { permissionsForRole, roleHasPermission, type Permission } from "../domain/rbac.js";
import { FixedWindowRateLimiter } from "../infrastructure/rate-limiter.js";
import { S } from "./schemas.js";
import type { Principal, CustomerPrincipal } from "../application/auth.js";
import type { CreateLicenseInput } from "../application/licensing-service.js";
import type { Container } from "../container.js";

const HTTP_FOR_CODE: Record<DomainErrorCode, number> = {
  NOT_FOUND: 404,
  INVALID_STATE_TRANSITION: 409,
  ACTIVATION_CODE_INVALID: 400,
  ACTIVATION_CODE_CONSUMED: 409,
  SEAT_LIMIT_REACHED: 409,
  LICENSE_NOT_ACTIVE: 403,
  LEASE_NOT_FOUND: 409,
  TRIAL_NOT_AVAILABLE: 403,
  TRIAL_ALREADY_USED: 409,
  VALIDATION: 400,
};

function bearer(req: FastifyRequest): string | null {
  const h = req.headers.authorization;
  if (!h || !h.startsWith("Bearer ")) return null;
  return h.slice("Bearer ".length);
}

function httpError(statusCode: number, message: string): Error {
  const e = new Error(message);
  (e as { statusCode?: number }).statusCode = statusCode;
  return e;
}

export function buildHttpServer(container: Container): FastifyInstance {
  const app = Fastify({
    // Structured logs; never log tokens/codes/secrets (we only log ids/status).
    logger: { level: container.config.env === "development" ? "info" : "warn" },
    // Behind a load balancer every request otherwise carries the LB's IP, which
    // would collapse all callers into ONE rate-limit bucket. Configure
    // TRUST_PROXY (true | hop count | CIDR list) to use X-Forwarded-For.
    trustProxy: container.config.trustProxy,
  });

  // Tolerate empty bodies on JSON requests: bodyless POSTs (e.g. /resume) must
  // not 400 just because the client set content-type: application/json.
  app.addContentTypeParser(
    "application/json",
    { parseAs: "string" },
    (_req, body, done) => {
      const s = (body as string).trim();
      if (s.length === 0) return done(null, {});
      try {
        done(null, JSON.parse(s));
      } catch (e) {
        (e as { statusCode?: number }).statusCode = 400;
        done(e as Error, undefined);
      }
    },
  );

  // Rate limiting for public (unauthenticated) endpoints — baseline protection
  // against activation-code brute force and endpoint abuse. Per-instance; see
  // rate-limiter.ts for the honest limitation note.
  const rateLimiter = new FixedWindowRateLimiter(
    Number(process.env.RATE_LIMIT_MAX ?? 120),
    Number(process.env.RATE_LIMIT_WINDOW_SECONDS ?? 60),
    container.clock,
  );

  const recordSecurityEvent = (
    type: string,
    subject: string | null,
    metadata: Record<string, string | number | boolean | null> = {},
  ): void => {
    // Fire-and-forget: security telemetry must never fail a request.
    void container.securityEvents
      .record({ id: `sec_${randomUUID()}`, type, subject, at: container.clock.now(), metadata })
      .catch(() => {});
  };

  const enforceRateLimit = (req: FastifyRequest, group: string): void => {
    if (!rateLimiter.check(`${req.ip}:${group}`)) {
      recordSecurityEvent("rate_limit_exceeded", req.ip, { group });
      throw httpError(429, "too many requests");
    }
  };

  /**
   * Authenticate a client request by proof-of-possession of a signed license
   * token bound to the calling device.
   *
   * An EXPIRED token is still accepted: possession is what is being proven, and
   * refreshing an expiring token is exactly what /validate is for. What must
   * hold is the signature, the issuer/audience, and — critically — that the
   * token is bound to the device making the claim. Unbound (null-binding)
   * tokens are rejected outright: they would otherwise act as a wildcard over
   * every device on the license.
   */
  const requireTokenProof = (
    req: FastifyRequest,
    token: string | undefined,
    deviceId: string | undefined,
    surface: string,
  ) => {
    if (!token || !deviceId) {
      throw new DomainError("VALIDATION", "token and deviceId are required");
    }
    const r = verifyLicenseToken(token, container.keyProvider.publicKeyStore(), {
      expectedAudience: container.config.tokenAudience,
      expectedIssuer: container.config.tokenIssuer,
      clock: container.clock,
    });
    const signatureValid =
      r.claims !== undefined &&
      !["bad_signature", "unknown_key", "malformed", "wrong_audience", "wrong_issuer"].includes(
        r.status,
      );
    if (!signatureValid) {
      recordSecurityEvent("auth_failed", req.ip, { surface });
      throw httpError(401, "invalid license token");
    }
    const claims = r.claims!;
    if (claims.deviceBinding !== hashDeviceBinding(deviceId)) {
      recordSecurityEvent("device_binding_mismatch", req.ip, { surface });
      throw httpError(403, "token is not bound to this device");
    }
    return claims;
  };

  // Authenticate a request to a Principal (401 if unknown / unconfigured).
  const authenticate = async (req: FastifyRequest): Promise<Principal> => {
    if (!container.principals.isConfigured()) {
      throw new DomainError(
        "VALIDATION",
        "admin auth not configured (set ADMIN_API_KEY/ADMIN_API_KEYS or AUTH_MODE=oidc)",
      );
    }
    const principal = await container.principals.resolve(bearer(req));
    if (!principal) {
      recordSecurityEvent("auth_failed", req.ip, { surface: "admin" });
      throw httpError(401, "unauthorized");
    }
    return principal;
  };

  // Authenticate + require a specific permission (403 if the role lacks it).
  const authorize = async (req: FastifyRequest, permission: Permission): Promise<Principal> => {
    const principal = await authenticate(req);
    if (!roleHasPermission(principal.role, permission)) {
      throw httpError(403, `forbidden: requires '${permission}'`);
    }
    return principal;
  };

  // CORS for the SPAs. Both portals are separate origins (admin and customer
  // run on different hosts/ports), so the allow-list carries both. We echo only
  // an allow-listed origin — never the caller's arbitrary Origin. Credentials
  // travel in the Authorization header, not cookies, so no Allow-Credentials.
  const allowedOrigins = [container.config.adminWebOrigin, container.config.customerWebOrigin]
    .filter((o): o is string => Boolean(o));
  const wildcard = allowedOrigins.includes("*");
  app.addHook("onRequest", async (req, reply) => {
    const origin = req.headers.origin;
    if (wildcard) {
      reply.header("access-control-allow-origin", "*");
    } else if (origin && allowedOrigins.includes(origin)) {
      reply.header("access-control-allow-origin", origin);
      reply.header("vary", "Origin");
    }
    reply.header("access-control-allow-methods", "GET,POST,OPTIONS");
    reply.header("access-control-allow-headers", "authorization,content-type");
    if (req.method === "OPTIONS") {
      return reply.code(204).send();
    }
  });

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof DomainError) {
      return reply
        .code(HTTP_FOR_CODE[err.code])
        .send({ error: { code: err.code, message: err.message } });
    }
    const status = (err as { statusCode?: number }).statusCode ?? 500;
    const message =
      status === 500 ? "internal error" : (err as { message?: string }).message ?? "error";
    const code =
      status === 400
        ? "VALIDATION"
        : status === 401
          ? "UNAUTHORIZED"
          : status === 403
            ? "FORBIDDEN"
            : status === 429
              ? "RATE_LIMITED"
              : "INTERNAL";
    return reply.code(status).send({ error: { code, message } });
  });

  // --- Health / readiness ---
  app.get("/health", async () => ({ status: "ok" }));
  app.get("/ready", async () => ({ status: "ready", keys: container.keyProvider.trustedKeyIds() }));

  // --- Public key distribution (SDK trust-store bootstrap; PUBLIC keys only) ---
  app.get("/api/v1/keys", async () => {
    const store = container.keyProvider.publicKeyStore();
    const kids = container.keyProvider.trustedKeyIds();
    return {
      activeKeyId: kids[0],
      keys: kids.map((kid) => ({
        kid,
        publicKeyPem: store.get(kid)?.export({ type: "spki", format: "pem" }).toString() ?? null,
      })),
    };
  });

  // --- Admin: identity (who am I + what can I do) ---
  app.get("/api/v1/admin/me", async (req, reply) => {
    const principal = await authenticate(req);
    return reply.send({
      subject: principal.subject,
      role: principal.role,
      permissions: permissionsForRole(principal.role),
    });
  });

  // --- Admin: products ---
  app.post("/api/v1/admin/products", { schema: { body: S.createProduct } }, async (req, reply) => {
    const principal = await authorize(req, "product:write");
    const body = req.body as { key: string; name: string };
    const product = await container.service.createProduct(body, principal.subject);
    return reply.code(201).send(product);
  });

  // --- Admin: licenses ---
  app.post("/api/v1/admin/licenses", { schema: { body: S.createLicense } }, async (req, reply) => {
    const principal = await authorize(req, "license:create");
    const license = await container.service.createLicense(req.body as CreateLicenseInput, principal.subject);
    return reply.code(201).send(license);
  });

  app.post("/api/v1/admin/licenses/:id/activation-codes", { schema: { body: S.generateActivationCode } }, async (req, reply) => {
    const principal = await authorize(req, "activation:issue");
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { maxActivations?: number };
    const { activationCode, record } = await container.service.generateActivationCode(
      id,
      body.maxActivations ?? 1,
      principal.subject,
    );
    // The plaintext code is returned ONCE and must never be logged.
    return reply.code(201).send({ activationCode, activationCodeId: record.id });
  });

  app.post("/api/v1/admin/licenses/:id/revoke", { schema: { body: S.reason } }, async (req, reply) => {
    const principal = await authorize(req, "license:revoke");
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { reason?: string };
    await container.service.revoke(id, body.reason ?? "revoked by admin", principal.subject);
    return reply.code(204).send();
  });

  app.post("/api/v1/admin/licenses/:id/suspend", { schema: { body: S.reason } }, async (req, reply) => {
    const principal = await authorize(req, "license:manage");
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { reason?: string };
    const license = await container.service.suspend(
      id,
      body.reason ?? "suspended by admin",
      principal.subject,
    );
    return reply.send(license);
  });

  app.post("/api/v1/admin/licenses/:id/resume", async (req, reply) => {
    const principal = await authorize(req, "license:manage");
    const { id } = req.params as { id: string };
    const license = await container.service.resume(id, principal.subject);
    return reply.send(license);
  });

  app.post("/api/v1/admin/licenses/:id/renew", { schema: { body: S.renew } }, async (req, reply) => {
    const principal = await authorize(req, "license:manage");
    const { id } = req.params as { id: string };
    const body = req.body as { expiresAt: number | null; maintenanceExpiresAt?: number | null };
    const license = await container.service.renew(id, body, principal.subject);
    return reply.send(license);
  });

  // --- Admin: read side (portal) ---
  app.get("/api/v1/admin/products", async (req, reply) => {
    await authorize(req, "product:read");
    return reply.send({ items: await container.service.listProducts() });
  });

  app.get("/api/v1/admin/licenses", async (req, reply) => {
    await authorize(req, "license:read");
    const q = req.query as Record<string, string | undefined>;
    const result = await container.service.listLicenses({
      customerId: q.customerId,
      productId: q.productId,
      status: q.status,
      limit: q.limit ? Number(q.limit) : undefined,
      offset: q.offset ? Number(q.offset) : undefined,
    });
    return reply.send(result);
  });

  app.get("/api/v1/admin/licenses/:id", async (req, reply) => {
    await authorize(req, "license:read");
    const { id } = req.params as { id: string };
    return reply.send(await container.service.getLicenseDetail(id));
  });

  app.get("/api/v1/admin/audit", async (req, reply) => {
    await authorize(req, "audit:read");
    const q = req.query as { licenseId?: string };
    return reply.send({ items: await container.service.listAuditEvents(q.licenseId) });
  });

  // --- Client: activation ---
  app.post("/api/v1/activate", { schema: { body: S.activate } }, async (req, reply) => {
    enforceRateLimit(req, "activate");
    const body = req.body as { activationCode: string; deviceId: string; deviceLabel?: string };
    const { token, license } = await container.service.activate({
      activationCode: body.activationCode,
      deviceId: body.deviceId,
      deviceLabel: body.deviceLabel ?? null,
    });
    return reply.send({ token, licenseId: license.id, status: license.status });
  });

  // --- Client: online validation ---
  app.post("/api/v1/validate", { schema: { body: S.validate } }, async (req, reply) => {
    enforceRateLimit(req, "validate");
    const body = req.body as { token: string; deviceId: string };
    // Proof-of-possession: without this, anyone holding a copied licenseId +
    // deviceId could mint fresh tokens forever. The licenseId is taken from the
    // VERIFIED claims, never from the request body.
    const claims = requireTokenProof(req, body.token, body.deviceId, "validate");
    const result = await container.service.validate({
      licenseId: claims.licenseId,
      deviceId: body.deviceId,
    });
    const code = result.status === "valid" ? 200 : 403;
    return reply.code(code).send(result);
  });

  // --- Client: self-service trial ---
  app.post("/api/v1/trial/start", { schema: { body: S.trialStart } }, async (req, reply) => {
    enforceRateLimit(req, "trial");
    const body = req.body as { productKey: string; deviceId: string; deviceLabel?: string };
    const { token, license } = await container.service.startTrial({
      productKey: body.productKey,
      deviceId: body.deviceId,
      deviceLabel: body.deviceLabel ?? null,
    });
    return reply.send({
      token,
      licenseId: license.id,
      status: license.status,
      expiresAt: license.expiresAt,
    });
  });

  // --- Client: deactivation (SDK-initiated seat release) ---
  // Authenticated by proof-of-possession: the caller must present a validly
  // SIGNED license token for the license it wants to deactivate a device on.
  app.post("/api/v1/deactivate", { schema: { body: S.deactivate } }, async (req, reply) => {
    enforceRateLimit(req, "deactivate");
    const body = req.body as { token: string; deviceId: string };
    // Binding is REQUIRED here: an unbound token would otherwise let its holder
    // deactivate any device on the license (seat-denial DoS).
    const claims = requireTokenProof(req, body.token, body.deviceId, "deactivate");
    await container.service.deactivateFromClient(claims.licenseId, body.deviceId);
    return reply.code(204).send();
  });

  // --- Client: offline activation (air-gapped) ---
  // Accepts a signed-request file, returns a signed-response file. Public like
  // /activate — the activation code in the request is the credential.
  app.post("/api/v1/offline/response", { schema: { body: S.offlineRequest } }, async (req, reply) => {
    enforceRateLimit(req, "offline");
    const response = await container.service.generateOfflineResponse(req.body as OfflineRequestFile);
    return reply
      .header("content-disposition", `attachment; filename="offline-response-${response.requestId}.json"`)
      .send(response);
  });

  // --- Client: floating (concurrent) seats ---
  app.post("/api/v1/floating/checkout", { schema: { body: S.floatingCheckout } }, async (req, reply) => {
    enforceRateLimit(req, "floating");
    const body = req.body as { token: string; deviceId: string; deviceLabel?: string };
    // Without proof-of-possession, knowing a licenseId would be enough to
    // consume every concurrent seat on it (seat-exhaustion DoS).
    const claims = requireTokenProof(req, body.token, body.deviceId, "floating");
    const result = await container.service.checkoutSeat({
      licenseId: claims.licenseId,
      deviceId: body.deviceId,
      deviceLabel: body.deviceLabel ?? null,
    });
    return reply.send(result);
  });

  app.post("/api/v1/floating/heartbeat", { schema: { body: S.floatingLease } }, async (req, reply) => {
    enforceRateLimit(req, "floating");
    const body = req.body as { leaseId: string; deviceId: string };
    return reply.send(await container.service.heartbeatSeat(body));
  });

  app.post("/api/v1/floating/return", { schema: { body: S.floatingLease } }, async (req, reply) => {
    enforceRateLimit(req, "floating");
    const body = req.body as { leaseId: string; deviceId: string };
    await container.service.returnSeat(body);
    return reply.code(204).send();
  });

  // --- Customer portal (scoped to the authenticated customerId) ---
  const authenticateCustomer = async (req: FastifyRequest): Promise<CustomerPrincipal> => {
    if (!container.customerPrincipals.isConfigured()) {
      throw new DomainError("VALIDATION", "customer auth not configured (set CUSTOMER_API_KEYS)");
    }
    const principal = await container.customerPrincipals.resolve(bearer(req));
    if (!principal) {
      recordSecurityEvent("auth_failed", req.ip, { surface: "customer" });
      throw httpError(401, "unauthorized");
    }
    return principal;
  };

  app.get("/api/v1/customer/me", async (req, reply) => {
    const c = await authenticateCustomer(req);
    return reply.send({ customerId: c.customerId, subject: c.subject });
  });

  app.get("/api/v1/customer/licenses", async (req, reply) => {
    const c = await authenticateCustomer(req);
    const items = await container.service.getCustomerLicenses(c.customerId);
    return reply.send({ items });
  });

  app.get("/api/v1/customer/licenses/:id", async (req, reply) => {
    const c = await authenticateCustomer(req);
    const { id } = req.params as { id: string };
    return reply.send(await container.service.getCustomerLicenseDetail(c.customerId, id));
  });

  app.post("/api/v1/customer/licenses/:id/devices/:activationId/deactivate", async (req, reply) => {
    const c = await authenticateCustomer(req);
    const { id, activationId } = req.params as { id: string; activationId: string };
    await container.service.deactivateDevice(c.customerId, id, activationId);
    return reply.code(204).send();
  });

  app.post("/api/v1/customer/licenses/:id/activation-reset", { schema: { body: S.activationReset } }, async (req, reply) => {
    const c = await authenticateCustomer(req);
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { note?: string };
    await container.service.requestActivationReset(c.customerId, id, body.note ?? "");
    return reply.code(202).send({ status: "requested" });
  });

  app.get("/api/v1/customer/licenses/:id/license-file", async (req, reply) => {
    const c = await authenticateCustomer(req);
    const { id } = req.params as { id: string };
    const file = await container.service.downloadLicenseFile(c.customerId, id);
    return reply
      .header("content-disposition", `attachment; filename="license-${id}.json"`)
      .send(file);
  });

  return app;
}
