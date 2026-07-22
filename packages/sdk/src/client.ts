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
import { randomUUID } from "node:crypto";
import {
  verifyLicenseToken,
  publicKeyFromPem,
  hashDeviceBinding,
  OFFLINE_SCHEMA_VERSION,
  type LicenseClaims,
  type PublicKeyStore,
  type OfflineRequestFile,
  type OfflineResponseFile,
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
  | "device_mismatch"
  | "not_activated"
  | "invalid";

export interface FloatingSeatHandle {
  leaseId: string;
  expiresAt: number;
}

export interface FloatingSeat extends FloatingSeatHandle {
  seatsUsed: number;
  maximumSeats: number;
}

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
  private lease: FloatingSeatHandle | null = null;
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

  /**
   * deactivate() — releases this device's seat on the server (best-effort,
   * authenticated by presenting the stored signed token as proof of
   * possession), returns any held floating seat, then clears local state.
   * Local state is ALWAYS cleared even if the server is unreachable; the seat
   * can then still be freed via the customer portal.
   */
  async deactivate(): Promise<void> {
    await this.returnSeat(); // no-op if no floating seat is held
    const state = await this.cfg.store.load();
    if (state) {
      try {
        await this.cfg.http.post("/api/v1/deactivate", {
          token: state.token,
          deviceId: state.deviceId,
        });
      } catch {
        /* best effort — offline deactivation still clears locally */
      }
    }
    await this.cfg.store.clear();
    this.last = DENIED("not_activated", LicensingErrorCode.NotActivated, "none", false);
  }

  /**
   * generateOfflineRequest() — produce a request file for air-gapped activation.
   * No network. The host app writes this to disk; the user carries it to a
   * connected machine / the portal, which returns a signed response file.
   */
  generateOfflineRequest(activationCode: string): OfflineRequestFile {
    return {
      schemaVersion: OFFLINE_SCHEMA_VERSION,
      kind: "offline-request",
      requestId: randomUUID(),
      deviceId: this.cfg.deviceId,
      deviceLabel: this.cfg.deviceLabel ?? null,
      activationCode,
      createdAt: this.clock.now(),
    };
  }

  /**
   * importOfflineResponse() — verify and apply a signed offline response file.
   * Verifies the token signature locally and that it is bound to THIS device,
   * then activates offline with no server contact.
   */
  async importOfflineResponse(response: OfflineResponseFile): Promise<LicenseSnapshot> {
    if (response?.kind !== "offline-response" || response.schemaVersion !== OFFLINE_SCHEMA_VERSION) {
      throw new LicensingError(LicensingErrorCode.OfflineFileInvalid);
    }
    if (response.deviceId !== this.cfg.deviceId) {
      throw new LicensingError(LicensingErrorCode.DeviceMismatch, "response device id mismatch");
    }
    const claims = this.verifyOrThrow(response.token);
    if (
      claims.deviceBinding !== null &&
      claims.deviceBinding !== hashDeviceBinding(this.cfg.deviceId)
    ) {
      throw new LicensingError(LicensingErrorCode.DeviceMismatch);
    }
    const state: StoredState = {
      licenseId: response.licenseId,
      deviceId: this.cfg.deviceId,
      token: response.token,
      lastServerTime: claims.issuedAt,
    };
    await this.cfg.store.save(state);
    this.last = this.snapshotFromToken(response.token, "offline_cache")!;
    return this.last;
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
      if (body.status === "device_not_activated") {
        // The server says this device holds no active seat (deactivated via a
        // portal, or reset). Clear the stale cache — do NOT fall back offline.
        await this.cfg.store.clear();
        this.last = DENIED("not_activated", LicensingErrorCode.NotActivated, "none", false);
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

  /**
   * checkoutSeat() — acquire a concurrent (floating) seat. Requires prior
   * activation (for the licenseId + deviceId). While holding a seat, call
   * heartbeatSeat() periodically (well within the returned lease window) and
   * returnSeat() on shutdown. If a client crashes, its lease expires and the
   * seat is reclaimed automatically.
   */
  async checkoutSeat(): Promise<FloatingSeat> {
    const state = await this.cfg.store.load();
    if (!state) throw new LicensingError(LicensingErrorCode.NotActivated);
    let res;
    try {
      res = await this.cfg.http.post("/api/v1/floating/checkout", {
        licenseId: state.licenseId,
        deviceId: state.deviceId,
        deviceLabel: this.cfg.deviceLabel ?? null,
      });
    } catch {
      throw new LicensingError(LicensingErrorCode.Network);
    }
    if (res.status === 409) throw new LicensingError(LicensingErrorCode.SeatUnavailable);
    if (res.status !== 200) {
      throw new LicensingError(LicensingErrorCode.NotSupported, `server ${res.status}`);
    }
    const body = res.body as {
      leaseId: string;
      expiresAt: number;
      seatsUsed: number;
      maximumSeats: number;
      token: string;
    };
    // Verify the entitlement token locally and refresh the snapshot.
    this.verifyOrThrow(body.token);
    const next: StoredState = {
      ...state,
      token: body.token,
      lastServerTime: Math.max(state.lastServerTime, this.clock.now()),
    };
    await this.cfg.store.save(next);
    this.last = this.snapshotFromToken(body.token, "online")!;
    this.lease = { leaseId: body.leaseId, expiresAt: body.expiresAt };
    return {
      leaseId: body.leaseId,
      expiresAt: body.expiresAt,
      seatsUsed: body.seatsUsed,
      maximumSeats: body.maximumSeats,
    };
  }

  /** heartbeatSeat() — extend the held lease. Throws LeaseExpired if it was reclaimed. */
  async heartbeatSeat(): Promise<{ expiresAt: number }> {
    if (!this.lease) throw new LicensingError(LicensingErrorCode.NoActiveLease);
    const state = await this.cfg.store.load();
    if (!state) throw new LicensingError(LicensingErrorCode.NotActivated);
    let res;
    try {
      res = await this.cfg.http.post("/api/v1/floating/heartbeat", {
        leaseId: this.lease.leaseId,
        deviceId: state.deviceId,
      });
    } catch {
      throw new LicensingError(LicensingErrorCode.Network);
    }
    if (res.status === 409) {
      this.lease = null; // lease was reclaimed; caller should re-checkout
      throw new LicensingError(LicensingErrorCode.LeaseExpired);
    }
    if (res.status !== 200) throw new LicensingError(LicensingErrorCode.NotSupported, `server ${res.status}`);
    const body = res.body as { expiresAt: number };
    this.lease = { ...this.lease, expiresAt: body.expiresAt };
    return { expiresAt: body.expiresAt };
  }

  /** returnSeat() — release the held concurrent seat (best-effort, idempotent). */
  async returnSeat(): Promise<void> {
    if (!this.lease) return;
    const state = await this.cfg.store.load();
    const leaseId = this.lease.leaseId;
    this.lease = null;
    if (!state) return;
    try {
      await this.cfg.http.post("/api/v1/floating/return", { leaseId, deviceId: state.deviceId });
    } catch {
      /* best effort — the lease will expire on its own if this fails */
    }
  }

  /** The currently held concurrent seat, if any. */
  getSeat(): FloatingSeatHandle | null {
    return this.lease;
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

    // Device binding: a device-bound (e.g. offline) token is only valid on the
    // device it was issued for. Prevents copying an offline file to another machine.
    if (c.deviceBinding !== null && c.deviceBinding !== hashDeviceBinding(this.cfg.deviceId)) {
      return {
        ...DENIED("device_mismatch", LicensingErrorCode.DeviceMismatch, source),
        offlineDaysRemaining: 0,
      };
    }

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
