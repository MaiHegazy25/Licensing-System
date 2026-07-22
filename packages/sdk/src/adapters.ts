/** Default Node adapters for the SDK ports. */
import { mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import type { Clock, HttpClient, HttpResponse, StoredState, TokenStore } from "./ports.js";

export const systemClock: Clock = {
  now: () => Math.floor(Date.now() / 1000),
};

/** fetch-based HTTP client. */
export class FetchHttpClient implements HttpClient {
  constructor(private readonly baseUrl: string) {}
  async post(path: string, body: unknown): Promise<HttpResponse> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    let parsed: unknown = null;
    try {
      parsed = await res.json();
    } catch {
      /* empty body */
    }
    return { status: res.status, body: parsed };
  }
}

/** In-memory store (tests). */
export class InMemoryTokenStore implements TokenStore {
  private state: StoredState | null = null;
  async load(): Promise<StoredState | null> {
    return this.state;
  }
  async save(state: StoredState): Promise<void> {
    this.state = state;
  }
  async clear(): Promise<void> {
    this.state = null;
  }
}

/**
 * File-backed store. NOTE: this is a baseline. Production builds should wrap OS
 * secure storage (DPAPI / Keychain / libsecret). The stored token is signed and
 * time-bounded, limiting the value of copying the file to another machine.
 */
export class FileTokenStore implements TokenStore {
  constructor(private readonly path: string) {}
  async load(): Promise<StoredState | null> {
    if (!existsSync(this.path)) return null;
    try {
      return JSON.parse(readFileSync(this.path, "utf8")) as StoredState;
    } catch {
      return null;
    }
  }
  async save(state: StoredState): Promise<void> {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(state), { mode: 0o600 });
  }
  async clear(): Promise<void> {
    if (existsSync(this.path)) rmSync(this.path);
  }
}
