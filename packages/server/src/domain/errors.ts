/** Typed domain errors carrying a stable machine-readable code. */
export type DomainErrorCode =
  | "NOT_FOUND"
  | "INVALID_STATE_TRANSITION"
  | "ACTIVATION_CODE_INVALID"
  | "ACTIVATION_CODE_CONSUMED"
  | "SEAT_LIMIT_REACHED"
  | "LICENSE_NOT_ACTIVE"
  | "LEASE_NOT_FOUND"
  | "VALIDATION";

export class DomainError extends Error {
  constructor(
    public readonly code: DomainErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "DomainError";
  }
}
