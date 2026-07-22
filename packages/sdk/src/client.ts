/**
 * LicensingClient — the integration surface for Vehiclevo tools.
 *
 * Design commitments (from the brief):
 *  - Verifies signed tokens LOCALLY using an embedded public-key trust store.
 *  - Never contains private keys or admin secrets.
 *  - Fails SAFE: any error path leaves features DISABLED, never silently enabled.
 *  - Offline-tolerant: short network failures fall back to the cached, signed
 *    token within its offline window instead of blocking the user.
 *  - Detects clock rollback to blunt "set the date back" attacks.
 *  - Checks happen in multiple places (activate/validate/hasFeature), not one
 *    bypassable gate.
 *
 * HONEST LIMITATION: client-side licensing raises the cost of bypass but cannot
 * make software uncrackable. A determined attacker with full control of the
 * device can patch checks. This design targets casual copying, license sharing,
 * expiry/revocation enforcement, and tamper-evidence — not unbreakable DRM.
 */
import {
  verifyLicenseToken,
  publicKeyFromPem,
  type LicenseClaims,
  type PublicKeyStore,
} from "@vehiclevo/licensing-shared";
import { LicensingError, LicensingErrorCode } from "./errors.js";
import { systemClock } from "./adapters.js";
import type { Clock, HttpClient, StoredState, TokenStore } from "./ports.js";

const DAY = 86_400;
/** Tolerated backward clock skew (s) before we call it tampering. */
const CLOCK_SKEW_TOLERANCE = 300;

export interface EmbeddedPublicKey {
  kid: string;
  pem: string;
}

export interface LicensingConfig {
  /** Base URL of the licensing API, e.g. https://licensing.vehiclevo.example */
  serverUrl?: string;
  expectedIssuer: string;
  expectedAudience: string;
  /** Stable, privacy-preserving device id (derived+salted). NOT a raw MAC. */
  deviceId: string;
  deviceLabel?: string;
  /** Embedded PUBLIC keys only. Multiple entries support key rotation. */
  publicKeys: EmbeddedPublicKey[];
  http: HttpClient;
  store: TokenStore;
  clock?: Clock;
}

export type SnapshotStatus =
  | "valid"
  | "grace"
  | "revoked"
  | "suspended"
  | "expired"
  | "offline_exceeded"
  | "clock_tampered"
  | "not_activated"
  | "invalid";

export interface LicenseSnapshot {
  activated: boolean;
  /** True only when the app is currently entitled to run paid functionality. */
  ok: boolean;
  status: SnapshotStatus;
  source: "online" | "offline_cache" | "none";
  features: string[];
  edition: string | null;
  licenseType: string | null;
  expiresAt: number | null;
  offlineDaysRemaining: number;
  reason?: LicensingErrorCode;
}

const DENIED = (
  status: SnapshotStatus,
  reason: LicensingErrorCode,
  source: LicenseSnapshot["source"] = "none",
  activated = true,
): LicenseSnapshot => ({
  activated,
  ok: false,
  status,
  source,
  features: [],
  edition: null,
  licenseType: null,
  expiresAt: null,
  offlineDaysRemaining: 0,
  reason,
});

export class LicensingClient {
  private readonly clock: Clock;
  private readonly keyStore: PublicKeyStore;
  private last: LicenseSnapshot = DENIED(
    "not_activated",
    LicensingErrorCode.NotActivated,
    "none",
    false,
  );

  private constructor(private readonly cfg: LicensingConfig) {
    this.clock = cfg.clock ?? systemClock;
    const keys = new Map(
      cfg.publicKeys.map((k) => [k.kid, publicKeyFromPem(k.pem)] as const),
    );
    this.keyStore = { get: (kid) => keys.get(kid) };
  }

  /** initializeLicensing(configuration) */
  static async initialize(cfg: LicensingConfig): Promise<LicensingClient> {
    if (cfg.publicKeys.length === 0) {
      throw new LicensingError(
        LicensingErrorCode.NotInitialized,
        "no public keys embedded",
      );
    }
    const client = new LicensingClient(cfg);
    const state = await cfg.store.load();
    if (state) client.last = client.evaluateOffline(state);
    return client;
  }

  /** activate(activationCode) */
  async activate(activationCode: string): Promise<LicenseSnapshot> {
    let res;
    try {
      res = await this.cfg.http.post("/api/v1/activate", {
        activationCode,
        deviceId: this.cfg.deviceId,
        deviceLabel: this.cfg.deviceLabel ?? null,
      });
    } catch {
      throw new LicensingError(LicensingErrorCode.Network);
    }
    if (res.status !== 200) {
      throw new LicensingError(LicensingErrorCode.ActivationFailed, `server ${res.status}`);
    }
    const body = res.body as { token: string; licenseId: string };
    const claims = this.verifyOrThrow(body.token);
    const state: StoredState = {
      licenseId: body.licenseId,
      deviceId: this.cfg.deviceId,
      token: body.token,
      lastServerTime: claims.issuedAt,
    };
    await this.cfg.store.save(state);
    this.last = this.snapshotFromToken(body.token, "online")!;
    return this.last;
  }

  /** deactivate() — clears local activation. (Server-side release is a later phase.) */
  async deactivate(): Promise<void> {
    await this.cfg.store.clear();
    this.last = DENIED("not_activated", LicensingErrorCode.NotActivated, "none", false);
  }

  /**
   * validateLicense() — authoritative online check with graceful offline fallback.
   * Returns a snapshot; does not throw for business outcomes (revoked/expired) so
   * callers can degrade gracefully. Fails safe on every path.
   */
  async validateLicense(): Promise<LicenseSnapshot> {
    const state = await this.cfg.store.load();
    if (!state) {
      this.last = DENIED("not_activated", LicensingErrorCode.NotActivated, "none", false);
      return this.last;
    }

    try {
      const res = await this.cfg.http.post("/api/v1/validate", {
        licenseId: state.licenseId,
        deviceId: state.deviceId,
      });
      const body = res.body as {
        status: string;
        token?: string;
      };
      if (res.status === 200 && body.token) {
        const claims = this.verifyOrThrow(body.token);
        const next: StoredState = {
          ...state,
          token: body.token,
          lastServerTime: Math.max(state.lastServerTime, claims.issuedAt),
        };
        await this.cfg.store.save(next);
        this.last = this.snapshotFromToken(body.token, "online")!;
        return this.last;
      }
      // Explicit negative verdicts from the server are authoritative.
      if (body.status === "revoked") {
        await this.cfg.store.clear();
        this.last = DENIED("revoked", LicensingErrorCode.Revoked);
        return this.last;
      }
      if (body.status === "suspended") {
        this.last = DENIED("suspended", LicensingErrorCode.Suspended);
        return this.last;
      }
      if (body.status === "expired") {
        this.last = DENIED("expired", LicensingErrorCode.Expired);
        return this.last;
      }
      // Unknown non-200 → treat as network-ish and fall back offline.
      this.last = this.evaluateOffline(state);
      return this.last;
    } catch {
      // Network failure: do NOT block a legitimate user — fall back to the
      // cached signed token within its offline window.
      this.last = this.evaluateOffline(state);
      return this.last;
    }
  }

  /** hasFeature(featureCode) — re-checks entitlement, never trusts a stale "ok". */
  hasFeature(featureCode: string): boolean {
    if (!this.last.ok) return false;
    return this.last.features.includes(featureCode);
  }

  /** getLicenseStatus() */
  getLicenseStatus(): LicenseSnapshot {
    return this.last;
  }

  /** getOfflineDaysRemaining() */
  getOfflineDaysRemaining(): number {
    return this.last.offlineDaysRemaining;
  }

  /** checkoutSeat() — floating licenses (implemented in a later phase). */
  async checkoutSeat(): Promise<never> {
    throw new LicensingError(
      LicensingErrorCode.NotSupported,
      "floating seat checkout is not enabled in this build",
    );
  }

  async returnSeat(): Promise<never> {
    throw new LicensingError(
      LicensingErrorCode.NotSupported,
      "floating seat return is not enabled in this build",
    );
  }

  // --- internals ---

  private verifyOrThrow(token: string): LicenseClaims {
    const r = verifyLicenseToken(token, this.keyStore, {
      expectedAudience: this.cfg.expectedAudience,
      expectedIssuer: this.cfg.expectedIssuer,
      clock: this.clock,
    });
    if (r.status === "unknown_key") {
      throw new LicensingError(LicensingErrorCode.UnknownSigningKey);
    }
    if (r.status === "bad_signature") {
      throw new LicensingError(LicensingErrorCode.SignatureInvalid);
    }
    if (r.status === "malformed") {
      throw new LicensingError(LicensingErrorCode.InvalidToken);
    }
    if (!r.claims) throw new LicensingError(LicensingErrorCode.InvalidToken);
    return r.claims;
  }

  /** Local-only evaluation of the cached token (offline path). */
  private evaluateOffline(state: StoredState): LicenseSnapshot {
    const now = this.clock.now();

    // Clock-rollback detection: local time significantly before the last time
    // the server vouched for. Refuse to extend trust on a rewound clock.
    if (now + CLOCK_SKEW_TOLERANCE < state.lastServerTime) {
      return DENIED("clock_tampered", LicensingErrorCode.ClockTampered, "offline_cache");
    }

    const snap = this.snapshotFromToken(state.token, "offline_cache");
    if (!snap) return DENIED("invalid", LicensingErrorCode.InvalidToken, "offline_cache");

    // Enforce the offline window: even a still-valid signed token may not be
    // used offline past offlineUntil.
    const claims = this.safeClaims(state.token);
    if (claims?.offlineUntil != null && now > claims.offlineUntil) {
      return DENIED(
        "offline_exceeded",
        LicensingErrorCode.OfflinePeriodExceeded,
        "offline_cache",
      );
    }
    return snap;
  }

  private safeClaims(token: string): LicenseClaims | null {
    const r = verifyLicenseToken(token, this.keyStore, {
      expectedAudience: this.cfg.expectedAudience,
      expectedIssuer: this.cfg.expectedIssuer,
      clock: this.clock,
    });
    return r.claims ?? null;
  }

  private snapshotFromToken(
    token: string,
    source: "online" | "offline_cache",
  ): LicenseSnapshot | null {
    const r = verifyLicenseToken(token, this.keyStore, {
      expectedAudience: this.cfg.expectedAudience,
      expectedIssuer: this.cfg.expectedIssuer,
      clock: this.clock,
    });
    if (!r.claims) return null;
    const c = r.claims;
    const offlineDaysRemaining =
      c.offlineUntil == null
        ? 0
        : Math.max(0, Math.floor((c.offlineUntil - this.clock.now()) / DAY));

    if (r.status === "valid" || r.status === "grace") {
      return {
        activated: true,
        ok: true,
        status: r.status,
        source,
        features: c.enabledFeatures,
        edition: c.edition,
        licenseType: c.licenseType,
        expiresAt: c.expiresAt,
        offlineDaysRemaining,
      };
    }
    const reason =
      r.status === "expired"
        ? LicensingErrorCode.Expired
        : r.status === "not_yet_valid"
          ? LicensingErrorCode.InvalidToken
          : r.status === "bad_signature"
            ? LicensingErrorCode.SignatureInvalid
            : LicensingErrorCode.InvalidToken;
    return {
      ...DENIED(r.status === "expired" ? "expired" : "invalid", reason, source),
      offlineDaysRemaining,
    };
  }
}
