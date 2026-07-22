export function fmtDate(epochSeconds: number | null | undefined): string {
  if (epochSeconds == null) return "—";
  return new Date(epochSeconds * 1000).toISOString().replace("T", " ").slice(0, 19) + "Z";
}
