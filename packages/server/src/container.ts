/**
 * Composition root. Wires ports to adapters. The vertical slice uses in-memory
 * repositories (zero external deps to run the demo); the Postgres adapters and
 * migrations exist for the production path and are selected when DATABASE_URL
 * is set (wired in a later phase).
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
import type { Clock } from "./application/ports.js";

export interface Container {
  service: LicensingService;
  keyProvider: SigningKeyProvider;
  config: AppConfig;
  audit: InMemoryAuditRepository;
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
  const audit = new InMemoryAuditRepository();
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
    products: new InMemoryProductRepository(),
    licenses: new InMemoryLicenseRepository(),
    activationCodes: new InMemoryActivationCodeRepository(),
    activations: new InMemoryActivationRepository(),
    revocations: new InMemoryRevocationRepository(),
    audit,
    tokenIssuer,
  });

  return { service, keyProvider, config: cfg, audit };
}
