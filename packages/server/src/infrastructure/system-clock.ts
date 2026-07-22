import type { Clock } from "../application/ports.js";

export const systemClock: Clock = {
  now: () => Math.floor(Date.now() / 1000),
};

/** Test clock whose time can be set/advanced deterministically. */
export class FakeClock implements Clock {
  constructor(private t: number) {}
  now(): number {
    return this.t;
  }
  set(t: number): void {
    this.t = t;
  }
  advance(seconds: number): void {
    this.t += seconds;
  }
}
