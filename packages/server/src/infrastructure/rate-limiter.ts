/**
 * Fixed-window rate limiter (per-process). Baseline protection against
 * brute-forcing activation codes and hammering public endpoints.
 *
 * HONEST LIMITATION: this is per-instance, in-memory state. In a multi-instance
 * deployment each instance enforces its own window, so the effective limit is
 * limit * instances; a shared store (Redis) or gateway-level limiting is the
 * production upgrade. Marked as such in the threat model.
 */
import type { Clock } from "../application/ports.js";

interface Window {
  start: number;
  count: number;
}

export class FixedWindowRateLimiter {
  private windows = new Map<string, Window>();

  constructor(
    private readonly limit: number,
    private readonly windowSeconds: number,
    private readonly clock: Clock,
  ) {}

  /** Returns true if the request is allowed; false if the limit is exceeded. */
  check(key: string): boolean {
    if (this.limit <= 0) return true; // limit 0 = disabled
    const now = this.clock.now();
    const w = this.windows.get(key);
    if (!w || now - w.start >= this.windowSeconds) {
      this.prune(now);
      this.windows.set(key, { start: now, count: 1 });
      return true;
    }
    w.count += 1;
    return w.count <= this.limit;
  }

  /** Drop stale windows so the map cannot grow without bound. */
  private prune(now: number): void {
    if (this.windows.size < 10_000) return;
    for (const [key, w] of this.windows) {
      if (now - w.start >= this.windowSeconds) this.windows.delete(key);
    }
  }
}
