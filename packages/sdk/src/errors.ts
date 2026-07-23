/** Stable, typed error codes the host application can branch on. */
export enum LicensingErrorCode {
  NotInitialized = "NOT_INITIALIZED",
  NotActivated = "NOT_ACTIVATED",
  ActivationFailed = "ACTIVATION_FAILED",
  InvalidToken = "INVALID_TOKEN",
  SignatureInvalid = "SIGNATURE_INVALID",
  UnknownSigningKey = "UNKNOWN_SIGNING_KEY",
  Expired = "EXPIRED",
  Revoked = "REVOKED",
  Suspended = "SUSPENDED",
  OfflinePeriodExceeded = "OFFLINE_PERIOD_EXCEEDED",
  ClockTampered = "CLOCK_TAMPERED",
  Network = "NETWORK",
  FeatureNotLicensed = "FEATURE_NOT_LICENSED",
  NotSupported = "NOT_SUPPORTED",
  SeatUnavailable = "SEAT_UNAVAILABLE",
  LeaseExpired = "LEASE_EXPIRED",
  NoActiveLease = "NO_ACTIVE_LEASE",
  DeviceMismatch = "DEVICE_MISMATCH",
  OfflineFileInvalid = "OFFLINE_FILE_INVALID",
  TrialNotAvailable = "TRIAL_NOT_AVAILABLE",
  TrialAlreadyUsed = "TRIAL_ALREADY_USED",
}

/** Human-friendly messages — safe to surface to end users. */
const MESSAGES: Record<LicensingErrorCode, string> = {
  [LicensingErrorCode.NotInitialized]: "Licensing has not been initialized.",
  [LicensingErrorCode.NotActivated]: "This product is not activated on this device.",
  [LicensingErrorCode.ActivationFailed]: "Activation failed. Please check your activation code.",
  [LicensingErrorCode.InvalidToken]: "The license file is invalid or corrupted.",
  [LicensingErrorCode.SignatureInvalid]: "The license could not be verified.",
  [LicensingErrorCode.UnknownSigningKey]: "The license was signed by an unrecognized key. Please update the application.",
  [LicensingErrorCode.Expired]: "Your license has expired.",
  [LicensingErrorCode.Revoked]: "Your license has been revoked. Please contact support.",
  [LicensingErrorCode.Suspended]: "Your license is currently suspended.",
  [LicensingErrorCode.OfflinePeriodExceeded]: "This device has been offline too long. Please reconnect to continue.",
  [LicensingErrorCode.ClockTampered]: "The system clock appears to have changed. Please correct the date and time.",
  [LicensingErrorCode.Network]: "Could not reach the licensing server.",
  [LicensingErrorCode.FeatureNotLicensed]: "This feature is not included in your license.",
  [LicensingErrorCode.NotSupported]: "This operation is not supported by your license type.",
  [LicensingErrorCode.SeatUnavailable]: "All concurrent seats are currently in use. Please try again shortly.",
  [LicensingErrorCode.LeaseExpired]: "Your concurrent seat has expired. Reconnecting…",
  [LicensingErrorCode.NoActiveLease]: "No concurrent seat is currently checked out.",
  [LicensingErrorCode.DeviceMismatch]: "This license file was issued for a different device.",
  [LicensingErrorCode.OfflineFileInvalid]: "The offline activation file is invalid or corrupted.",
  [LicensingErrorCode.TrialNotAvailable]: "A free trial is not available for this product.",
  [LicensingErrorCode.TrialAlreadyUsed]: "The free trial has already been used on this device.",
};

export class LicensingError extends Error {
  constructor(
    public readonly code: LicensingErrorCode,
    /** Optional developer detail; the `.userMessage` is what to show end users. */
    detail?: string,
  ) {
    super(detail ? `${MESSAGES[code]} (${detail})` : MESSAGES[code]);
    this.name = "LicensingError";
  }
  get userMessage(): string {
    return MESSAGES[this.code];
  }
}
