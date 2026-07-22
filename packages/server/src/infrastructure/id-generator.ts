import { randomUUID } from "node:crypto";
import type { IdGenerator } from "../application/ports.js";

/** Prefixed UUIDv4 ids, e.g. "lic_9f1c...". Opaque and non-enumerable. */
export class UuidIdGenerator implements IdGenerator {
  next(prefix: string): string {
    return `${prefix}_${randomUUID()}`;
  }
}
