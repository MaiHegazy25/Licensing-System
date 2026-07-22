/**
 * Composition root. Wires ports to adapters.
 *
 * Persistence is selected by config: when `databaseUrl` is set the Postgres
 * adapters are used; otherwise in-memory adapters run the demo/tests with zero
 * external dependencies. Both implement the same repository ports, so the
 * application/domain layers are unaware of the choice.
 */
import type { AppConfig } from "./config.js";
import { LicensingService } from "./application/licensing-service.js";
import { HmacActivationCodeService } from "./infrastructure/activation-code-service.js";
import { UuidIdGenerator } from "./infrastructure/id-generator.js";
import { systemClock } from "./infrastructure/system-clock.js";
import { LocalKeyProvider } from "./infrastructure/signing/local-key-provider.js";
import type { SigningKeyProvider } from "./infrastructure/signing/key-provider.js";
import { SigningTokenIssuer } from "./infrastructure/signing/token-issuer.js";
import {
  InMemoryActivationCodeRepository,
  InMemoryActivationRepository,
  InMemoryAuditRepository,
  InMemoryLicenseRepository,
  InMemoryProductRepository,
  InMemoryRevocationRepository,
} from "./infrastructure/persistence/memory.js";
import {
  PgActivationCodeRepository,
  PgActivationRepository,
  PgAuditRepository,
  PgLicenseRepository,
  PgProductRepository,
  PgRevocationRepository,
} from "./infrastructure/persistence/postgres.js";
import { createPool, type Pool } from "./infrastructure/persistence/pool.js";
import type {
  ActivationCodeRepository,
  ActivationRepository,
  AuditRepository,
  Clock,
  LicenseRepository,
  ProductRepository,
  RevocationRepository,
} from "./application/ports.js";
import { buildPrincipalResolver } from "./infrastructure/auth/resolver-factory.js";
import { CustomerApiKeyResolver } from "./infrastructure/auth/customer-api-key-resolver.js";
import type { PrincipalResolver, CustomerPrincipalResolver } from "./application/auth.js";

export interface Container {
  service: LicensingService;
  keyProvider: SigningKeyProvider;
  principals: PrincipalResolver;
  customerPrincipals: CustomerPrincipalResolver;
  config: AppConfig;
  audit: AuditRepository;
  /** Underlying pool when Postgres-backed (for migrations / shutdown); else null. */
  pool: Pool | null;
  /** Release resources (closes the pool if any). */
  close(): Promise<void>;
}

interface RepoSet {
  products: ProductRepository;
  licenses: LicenseRepository;
  activationCodes: ActivationCodeRepository;
  activations: ActivationRepository;
  revocations: RevocationRepository;
  audit: AuditRepository;
  pool: Pool | null;
}

function buildRepos(cfg: AppConfig): RepoSet {
  if (cfg.databaseUrl) {
    const pool = createPool(cfg.databaseUrl);
    return {
      products: new PgProductRepository(pool),
      licenses: new PgLicenseRepository(pool),
      activationCodes: new PgActivationCodeRepository(pool),
      activations: new PgActivationRepository(pool),
      revocations: new PgRevocationRepository(pool),
      audit: new PgAuditRepository(pool),
      pool,
    };
  }
  return {
    products: new InMemoryProductRepository(),
    licenses: new InMemoryLicenseRepository(),
    activationCodes: new InMemoryActivationCodeRepository(),
    activations: new InMemoryActivationRepository(),
    revocations: new InMemoryRevocationRepository(),
    audit: new InMemoryAuditRepository(),
    pool: null,
  };
}

export function buildContainer(
  cfg: AppConfig,
  clock: Clock = systemClock,
  injectedKeyProvider?: SigningKeyProvider,
): Container {
  if (!injectedKeyProvider && cfg.signingProvider !== "local") {
    throw new Error(
      "only the 'local' signing provider is wired in this slice; a KMS provider implements the same SigningKeyProvider interface",
    );
  }
  const keyProvider =
    injectedKeyProvider ??
    LocalKeyProvider.fromDirectory(cfg.localKeysDir, cfg.activeSigningKeyId);

  const ids = new UuidIdGenerator();
  const repos = buildRepos(cfg);
  const tokenIssuer = new SigningTokenIssuer(
    keyProvider,
    {
      issuer: cfg.tokenIssuer,
      audience: cfg.tokenAudience,
      tokenTtlSeconds: cfg.tokenTtlSeconds,
    },
    clock,
    ids,
  );

  const service = new LicensingService({
    clock,
    ids,
    codes: new HmacActivationCodeService(cfg.activationCodePepper),
    products: repos.products,
    licenses: repos.licenses,
    activationCodes: repos.activationCodes,
    activations: repos.activations,
    revocations: repos.revocations,
    audit: repos.audit,
    tokenIssuer,
  });

  const principals = buildPrincipalResolver();
  const customerPrincipals = CustomerApiKeyResolver.fromEnv();

  return {
    service,
    keyProvider,
    principals,
    customerPrincipals,
    config: cfg,
    audit: repos.audit,
    pool: repos.pool,
    async close() {
      if (repos.pool) await repos.pool.end();
    },
  };
}
