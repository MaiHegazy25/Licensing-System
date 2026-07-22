/**
 * HTTP API (Fastify). Thin transport layer over the LicensingService.
 *
 * AuthN/Z: every admin route authenticates the bearer token to a Principal
 * (subject + role) via the PrincipalResolver, then authorizes a specific
 * Permission against the role. The API-key resolver is the dev/slice adapter;
 * PRODUCTION swaps in an OIDC-token resolver behind the same port — routes and
 * the permission matrix are unchanged.
 */
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { DomainError, type DomainErrorCode } from "../domain/errors.js";
import { permissionsForRole, roleHasPermission, type Permission } from "../domain/rbac.js";
import type { Principal, CustomerPrincipal } from "../application/auth.js";
import type { Container } from "../container.js";

const HTTP_FOR_CODE: Record<DomainErrorCode, number> = {
  NOT_FOUND: 404,
  INVALID_STATE_TRANSITION: 409,
  ACTIVATION_CODE_INVALID: 400,
  ACTIVATION_CODE_CONSUMED: 409,
  SEAT_LIMIT_REACHED: 409,
  LICENSE_NOT_ACTIVE: 403,
  LEASE_NOT_FOUND: 409,
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

  // Authenticate a request to a Principal (401 if unknown / unconfigured).
  const authenticate = async (req: FastifyRequest): Promise<Principal> => {
    if (!container.principals.isConfigured()) {
      throw new DomainError(
        "VALIDATION",
        "admin auth not configured (set ADMIN_API_KEY/ADMIN_API_KEYS or AUTH_MODE=oidc)",
      );
    }
    const principal = await container.principals.resolve(bearer(req));
    if (!principal) throw httpError(401, "unauthorized");
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

  // CORS for the admin SPA (dev serves it on a different origin). The allowed
  // origin is configurable; credentials are sent via Authorization header, not
  // cookies, so we do not need Allow-Credentials.
  const allowedOrigin = process.env.ADMIN_WEB_ORIGIN ?? "*";
  app.addHook("onRequest", async (req, reply) => {
    reply.header("access-control-allow-origin", allowedOrigin);
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
      status === 401 ? "UNAUTHORIZED" : status === 403 ? "FORBIDDEN" : "INTERNAL";
    return reply.code(status).send({ error: { code, message } });
  });

  // --- Health / readiness ---
  app.get("/health", async () => ({ status: "ok" }));
  app.get("/ready", async () => ({ status: "ready", keys: container.keyProvider.trustedKeyIds() }));

  // --- Public key distribution (SDK trust-store bootstrap; public keys only) ---
  app.get("/api/v1/keys", async () => {
    // In production serve PEMs of trusted public keys keyed by kid.
    return { activeKeyId: container.keyProvider.trustedKeyIds()[0], trustedKeyIds: container.keyProvider.trustedKeyIds() };
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
  app.post("/api/v1/admin/products", async (req, reply) => {
    const principal = await authorize(req, "product:write");
    const body = req.body as { key: string; name: string };
    const product = await container.service.createProduct(body, principal.subject);
    return reply.code(201).send(product);
  });

  // --- Admin: licenses ---
  app.post("/api/v1/admin/licenses", async (req, reply) => {
    const principal = await authorize(req, "license:create");
    const license = await container.service.createLicense(req.body as never, principal.subject);
    return reply.code(201).send(license);
  });

  app.post("/api/v1/admin/licenses/:id/activation-codes", async (req, reply) => {
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

  app.post("/api/v1/admin/licenses/:id/revoke", async (req, reply) => {
    const principal = await authorize(req, "license:revoke");
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { reason?: string };
    await container.service.revoke(id, body.reason ?? "revoked by admin", principal.subject);
    return reply.code(204).send();
  });

  app.post("/api/v1/admin/licenses/:id/suspend", async (req, reply) => {
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

  app.post("/api/v1/admin/licenses/:id/renew", async (req, reply) => {
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
  app.post("/api/v1/activate", async (req, reply) => {
    const body = req.body as { activationCode: string; deviceId: string; deviceLabel?: string };
    const { token, license } = await container.service.activate({
      activationCode: body.activationCode,
      deviceId: body.deviceId,
      deviceLabel: body.deviceLabel ?? null,
    });
    return reply.send({ token, licenseId: license.id, status: license.status });
  });

  // --- Client: online validation ---
  app.post("/api/v1/validate", async (req, reply) => {
    const body = req.body as { licenseId: string; deviceId: string };
    const result = await container.service.validate(body);
    const code = result.status === "valid" ? 200 : 403;
    return reply.code(code).send(result);
  });

  // --- Client: offline activation (air-gapped) ---
  // Accepts a signed-request file, returns a signed-response file. Public like
  // /activate — the activation code in the request is the credential.
  app.post("/api/v1/offline/response", async (req, reply) => {
    const response = await container.service.generateOfflineResponse(req.body as never);
    return reply
      .header("content-disposition", `attachment; filename="offline-response-${response.requestId}.json"`)
      .send(response);
  });

  // --- Client: floating (concurrent) seats ---
  app.post("/api/v1/floating/checkout", async (req, reply) => {
    const body = req.body as { licenseId: string; deviceId: string; deviceLabel?: string };
    const result = await container.service.checkoutSeat({
      licenseId: body.licenseId,
      deviceId: body.deviceId,
      deviceLabel: body.deviceLabel ?? null,
    });
    return reply.send(result);
  });

  app.post("/api/v1/floating/heartbeat", async (req, reply) => {
    const body = req.body as { leaseId: string; deviceId: string };
    return reply.send(await container.service.heartbeatSeat(body));
  });

  app.post("/api/v1/floating/return", async (req, reply) => {
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
    if (!principal) throw httpError(401, "unauthorized");
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

  app.post("/api/v1/customer/licenses/:id/activation-reset", async (req, reply) => {
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
