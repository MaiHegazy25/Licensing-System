/**
 * SDK dependency ports — all injectable for DI and mocking in host-app tests.
 * The default adapters (see adapters.ts) cover Node; native SDK ports (C++/Java)
 * mirror these same interfaces.
 */

export interface HttpResponse {
  status: number;
  body: unknown;
}

/** Minimal HTTP transport. Real impls use fetch/OS HTTP with TLS pinning options. */
export interface HttpClient {
  post(path: string, body: unknown): Promise<HttpResponse>;
}

/**
 * Persistent storage for activation state. Production adapters use OS-protected
 * storage (DPAPI on Windows, Keychain on macOS, libsecret on Linux). The token
 * is signed and independently verifiable, so storage protects against casual
 * copying, not against a determined attacker — see SECURITY notes in README.
 */
export interface TokenStore {
  load(): Promise<StoredState | null>;
  save(state: StoredState): Promise<void>;
  clear(): Promise<void>;
}

export interface StoredState {
  licenseId: string;
  deviceId: string;
  token: string;
  /** Highest server-issued time observed (epoch s). Used for clock-rollback detection. */
  lastServerTime: number;
}

export interface Clock {
  now(): number; // epoch seconds
}
