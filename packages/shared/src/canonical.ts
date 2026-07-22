/**
 * Deterministic (canonical) JSON serialization.
 *
 * We need byte-for-byte identical output on the signing side (server) and the
 * verifying side (SDK) so a signature computed over the payload verifies
 * regardless of language runtime or object key ordering. This follows the
 * spirit of RFC 8785 (JSON Canonicalization Scheme): object keys are sorted
 * lexicographically by UTF-16 code unit, no insignificant whitespace, and
 * arrays preserve order.
 *
 * We intentionally reject values that have no canonical representation
 * (undefined, functions, NaN, Infinity) rather than silently dropping them,
 * because a dropped field is a security-relevant difference.
 */

export function canonicalize(value: unknown): string {
  return serialize(value);
}

function serialize(value: unknown): string {
  if (value === null) return "null";

  const t = typeof value;

  if (t === "number") {
    if (!Number.isFinite(value as number)) {
      throw new Error("canonicalize: non-finite number is not serializable");
    }
    return JSON.stringify(value);
  }

  if (t === "boolean") return value ? "true" : "false";
  if (t === "string") return JSON.stringify(value);

  if (t === "undefined" || t === "function" || t === "symbol" || t === "bigint") {
    throw new Error(`canonicalize: value of type ${t} is not serializable`);
  }

  if (Array.isArray(value)) {
    return "[" + value.map(serialize).join(",") + "]";
  }

  // Plain object: sort keys, skip undefined members (JSON semantics).
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const v = obj[key];
    if (typeof v === "undefined") continue;
    parts.push(JSON.stringify(key) + ":" + serialize(v));
  }
  return "{" + parts.join(",") + "}";
}
