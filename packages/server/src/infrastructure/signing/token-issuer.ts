/** Builds signed license tokens from License state + config. */
import {
  signLicenseToken,
  type LicenseClaims,
} from "@vehiclevo/licensing-shared";
import type { License } from "../../domain/license.js";
import type { Clock, IdGenerator } from "../../application/ports.js";
import type { IssueOptions, IssuedToken, TokenIssuer } from "../../application/token-issuer.js";
import type { SigningKeyProvider } from "./key-provider.js";

const SCHEMA_VERSION = 1;

export interface TokenIssuerConfig {
  issuer: string;
  audience: string;
  /** How long an issued online token stays valid before the SDK must re-validate. */
  tokenTtlSeconds: number;
}

export class SigningTokenIssuer implements TokenIssuer {
  constructor(
    private readonly keys: SigningKeyProvider,
    private readonly cfg: TokenIssuerConfig,
    private readonly clock: Clock,
    private readonly ids: IdGenerator,
  ) {}

  async issue(license: License, opts: IssueOptions = {}): Promise<IssuedToken> {
    const now = this.clock.now();
    const signer = this.keys.activeSigner();

    // Default token validity = min(license expiry, now + short TTL). The short TTL
    // forces periodic re-validation so revocation propagates without waiting for
    // license expiry. Offline tokens override this with a long-lived expiry.
    const ttlExpiry = now + this.cfg.tokenTtlSeconds;
    const tokenExpiresAt =
      opts.expiresAtOverride !== undefined
        ? opts.expiresAtOverride
        : license.expiresAt === null
          ? ttlExpiry
          : Math.min(ttlExpiry, license.expiresAt);

    const tokenId = this.ids.next("tok");
    const claims: LicenseClaims = {
      schemaVersion: SCHEMA_VERSION,
      tokenId,
      licenseId: license.id,
      customerId: license.customerId,
      organizationId: license.organizationId,
      productId: license.productId,
      edition: license.edition,
      enabledFeatures: license.enabledFeatures,
      licenseType: license.licenseType,
      issuedAt: now,
      notBefore: license.notBefore,
      expiresAt: tokenExpiresAt,
      maintenanceExpiresAt: license.maintenanceExpiresAt,
      maximumSeats: license.maximumSeats,
      deviceBinding: opts.deviceBinding ?? null,
      offlineUntil:
        opts.offlineUntilOverride !== undefined ? opts.offlineUntilOverride : license.offlineUntil,
      gracePeriodSeconds: license.gracePeriodSeconds,
      issuer: this.cfg.issuer,
      audience: this.cfg.audience,
    };

    const token = await signLicenseToken(claims, signer);
    return { token, tokenId, keyId: signer.kid, expiresAt: tokenExpiresAt };
  }
}
