export function fmtDate(epochSeconds: number | null | undefined): string {
  if (epochSeconds == null) return "—";
  return new Date(epochSeconds * 1000).toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function daysFromNow(days: number): number {
  return Math.floor(Date.now() / 1000) + days * 86400;
}

export function toEpochSeconds(dateInput: string): number | null {
  if (!dateInput) return null;
  const ms = Date.parse(dateInput);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}
