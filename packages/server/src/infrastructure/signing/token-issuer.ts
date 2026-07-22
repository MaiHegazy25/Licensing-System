/** Builds signed license tokens from License state + config. */
import {
  signLicenseToken,
  type LicenseClaims,
} from "@vehiclevo/licensing-shared";
import type { License } from "../../domain/license.js";
import type { Clock, IdGenerator } from "../../application/ports.js";
import type { IssuedToken, TokenIssuer } from "../../application/token-issuer.js";
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

  async issue(license: License): Promise<IssuedToken> {
    const now = this.clock.now();
    const signer = this.keys.activeSigner();

    // Token validity = min(license expiry, now + short TTL). The short TTL forces
    // periodic re-validation so revocation propagates without waiting for license
    // expiry. offlineUntil governs the longer no-contact window.
    const ttlExpiry = now + this.cfg.tokenTtlSeconds;
    const tokenExpiresAt =
      license.expiresAt === null ? ttlExpiry : Math.min(ttlExpiry, license.expiresAt);

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
      deviceBinding: null,
      offlineUntil: license.offlineUntil,
      gracePeriodSeconds: license.gracePeriodSeconds,
      issuer: this.cfg.issuer,
      audience: this.cfg.audience,
    };

    const token = await signLicenseToken(claims, signer);
    return { token, tokenId, keyId: signer.kid, expiresAt: tokenExpiresAt };
  }
}
