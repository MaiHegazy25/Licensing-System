/**
 * Activation code generation + hashing.
 *
 * Codes are HIGH-ENTROPY random values (>=100 bits), so a fast keyed hash
 * (HMAC-SHA-256 with a server-side pepper) is sufficient and appropriate —
 * slow password hashing (Argon2id) targets low-entropy human secrets, not
 * random codes. The pepper comes from a secrets manager; only the hash is
 * stored, so a DB leak does not expose usable codes. Comparison is constant
 * time to avoid timing oracles.
 */
import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";
import type { ActivationCodeService } from "../application/ports.js";

// Crockford base32 alphabet (no I, L, O, U — avoids ambiguity).
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function encodeGroups(bytes: Buffer): string {
  let out = "";
  for (const b of bytes) out += ALPHABET[b % 32];
  // Format as XXXXX-XXXXX-XXXXX-XXXXX for readability.
  return out.match(/.{1,5}/g)!.join("-");
}

export class HmacActivationCodeService implements ActivationCodeService {
  constructor(private readonly pepper: string) {
    if (!pepper || pepper.length < 16) {
      throw new Error("ACTIVATION_CODE_PEPPER must be set (>=16 chars)");
    }
  }

  generate(): { plaintext: string; hash: string } {
    // 20 symbols * 5 bits ≈ 100 bits of entropy.
    const plaintext = encodeGroups(randomBytes(20));
    return { plaintext, hash: this.hash(plaintext) };
  }

  hash(plaintext: string): string {
    return createHmac("sha256", this.pepper)
      .update(plaintext.trim().toUpperCase())
      .digest("hex");
  }

  verify(plaintext: string, hash: string): boolean {
    const a = Buffer.from(this.hash(plaintext), "hex");
    const b = Buffer.from(hash, "hex");
    return a.length === b.length && timingSafeEqual(a, b);
  }
}
