/**
 * HTTP API (Fastify). Thin transport layer over the LicensingService.
 *
 * AuthN/Z here is intentionally minimal for the vertical slice: admin routes
 * require a bearer token compared in constant time against ADMIN_API_KEY.
 * PRODUCTION replaces this with OIDC (Entra ID / Keycloak) + the five RBAC
 * roles from the brief — the guard is isolated so that swap is localized.
 */
import { timingSafeEqual } from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { DomainError, type DomainErrorCode } from "../domain/errors.js";
import type { Container } from "../container.js";

const HTTP_FOR_CODE: Record<DomainErrorCode, number> = {
  NOT_FOUND: 404,
  INVALID_STATE_TRANSITION: 409,
  ACTIVATION_CODE_INVALID: 400,
  ACTIVATION_CODE_CONSUMED: 409,
  SEAT_LIMIT_REACHED: 409,
  LICENSE_NOT_ACTIVE: 403,
  VALIDATION: 400,
};

function bearer(req: FastifyRequest): string | null {
  const h = req.headers.authorization;
  if (!h || !h.startsWith("Bearer ")) return null;
  return h.slice("Bearer ".length);
}

function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
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

  const adminKey = process.env.ADMIN_API_KEY ?? "";

  const requireAdmin = async (req: FastifyRequest): Promise<void> => {
    if (!adminKey) {
      throw new DomainError("VALIDATION", "admin auth not configured (set ADMIN_API_KEY)");
    }
    const token = bearer(req);
    if (!token || !constantTimeEquals(token, adminKey)) {
      const e = new Error("unauthorized");
      (e as { statusCode?: number }).statusCode = 401;
      throw e;
    }
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
    return reply
      .code(status)
      .send({ error: { code: status === 401 ? "UNAUTHORIZED" : "INTERNAL", message } });
  });

  // --- Health / readiness ---
  app.get("/health", async () => ({ status: "ok" }));
  app.get("/ready", async () => ({ status: "ready", keys: container.keyProvider.trustedKeyIds() }));

  // --- Public key distribution (SDK trust-store bootstrap; public keys only) ---
  app.get("/api/v1/keys", async () => {
    // In production serve PEMs of trusted public keys keyed by kid.
    return { activeKeyId: container.keyProvider.trustedKeyIds()[0], trustedKeyIds: container.keyProvider.trustedKeyIds() };
  });

  // --- Admin: products ---
  app.post("/api/v1/admin/products", async (req, reply) => {
    await requireAdmin(req);
    const body = req.body as { key: string; name: string };
    const product = await container.service.createProduct(body);
    return reply.code(201).send(product);
  });

  // --- Admin: licenses ---
  app.post("/api/v1/admin/licenses", async (req, reply) => {
    await requireAdmin(req);
    const license = await container.service.createLicense(req.body as never);
    return reply.code(201).send(license);
  });

  app.post("/api/v1/admin/licenses/:id/activation-codes", async (req, reply) => {
    await requireAdmin(req);
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { maxActivations?: number };
    const { activationCode, record } = await container.service.generateActivationCode(
      id,
      body.maxActivations ?? 1,
    );
    // The plaintext code is returned ONCE and must never be logged.
    return reply.code(201).send({ activationCode, activationCodeId: record.id });
  });

  app.post("/api/v1/admin/licenses/:id/revoke", async (req, reply) => {
    await requireAdmin(req);
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { reason?: string };
    await container.service.revoke(id, body.reason ?? "revoked by admin");
    return reply.code(204).send();
  });

  app.post("/api/v1/admin/licenses/:id/suspend", async (req, reply) => {
    await requireAdmin(req);
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { reason?: string };
    const license = await container.service.suspend(id, body.reason ?? "suspended by admin");
    return reply.send(license);
  });

  app.post("/api/v1/admin/licenses/:id/resume", async (req, reply) => {
    await requireAdmin(req);
    const { id } = req.params as { id: string };
    const license = await container.service.resume(id);
    return reply.send(license);
  });

  app.post("/api/v1/admin/licenses/:id/renew", async (req, reply) => {
    await requireAdmin(req);
    const { id } = req.params as { id: string };
    const body = req.body as { expiresAt: number | null; maintenanceExpiresAt?: number | null };
    const license = await container.service.renew(id, body);
    return reply.send(license);
  });

  // --- Admin: read side (portal) ---
  app.get("/api/v1/admin/products", async (req, reply) => {
    await requireAdmin(req);
    return reply.send({ items: await container.service.listProducts() });
  });

  app.get("/api/v1/admin/licenses", async (req, reply) => {
    await requireAdmin(req);
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
    await requireAdmin(req);
    const { id } = req.params as { id: string };
    return reply.send(await container.service.getLicenseDetail(id));
  });

  app.get("/api/v1/admin/audit", async (req, reply) => {
    await requireAdmin(req);
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

  return app;
}
