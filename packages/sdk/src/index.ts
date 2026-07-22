export * from "./client.js";
export * from "./errors.js";
export * from "./ports.js";
export * from "./adapters.js";

import { LicensingClient, type LicensingConfig } from "./client.js";

/** Convenience matching the brief's `initializeLicensing(configuration)`. */
export function initializeLicensing(config: LicensingConfig): Promise<LicensingClient> {
  return LicensingClient.initialize(config);
}
