/**
 * Typed admin API client. Framework-agnostic and injectable (accepts a `fetch`
 * impl and a token getter) so it is unit-testable without a browser or React.
 * The admin key is sent as a Bearer token and never persisted by this module —
 * the caller decides storage (see auth.tsx: sessionStorage, cleared on logout).
 */
export type LicenseStatus = "draft" | "active" | "suspended" | "expired" | "revoked";
export type LicenseType =
  | "named_user" | "device" | "floating" | "subscription" | "perpetual" | "trial";

export interface TrialPolicy {
  enabled: boolean;
  days: number;
  edition: string;
  features: string[];
}

export interface Product {
  id: string;
  key: string;
  name: string;
  createdAt: number;
  trial: TrialPolicy;
}

export interface License {
  id: string;
  customerId: string;
  organizationId: string | null;
  productId: string;
  edition: string;
  enabledFeatures: string[];
  licenseType: LicenseType;
  status: LicenseStatus;
  maximumSeats: number;
  notBefore: number;
  expiresAt: number | null;
  maintenanceExpiresAt: number | null;
  gracePeriodSeconds: number;
  offlineUntil: number | null;
  createdAt: number;
  updatedAt: number;
  version: number;
}

export interface Activation {
  id: string;
  deviceId: string;
  deviceLabel: string | null;
  status: "active" | "deactivated";
  activatedAt: number;
  lastSeenAt: number;
}

export interface ActivationCodeMeta {
  id: string;
  status: "unused" | "consumed" | "revoked";
  maxActivations: number;
  usedActivations: number;
  createdAt: number;
  consumedAt: number | null;
}

export interface AuditEvent {
  id: string;
  type: string;
  licenseId: string | null;
  actor: string;
  at: number;
  metadata: Record<string, unknown>;
}

export interface FloatingLease {
  id: string;
  deviceId: string;
  deviceLabel: string | null;
  acquiredAt: number;
  expiresAt: number;
}

export interface LicenseDetail {
  license: License;
  activations: Activation[];
  activationCodes: ActivationCodeMeta[];
  floatingLeases: FloatingLease[];
  revocation: { reason: string; revokedAt: number } | null;
  audit: AuditEvent[];
}

export interface CreateLicenseInput {
  customerId: string;
  organizationId?: string | null;
  productId: string;
  edition: string;
  enabledFeatures: string[];
  licenseType: LicenseType;
  maximumSeats: number;
  expiresAt?: number | null;
  maintenanceExpiresAt?: number | null;
  gracePeriodSeconds?: number;
  offlineUntil?: number | null;
}

export type Role =
  | "system_admin" | "license_admin" | "sales_ops" | "support" | "auditor";

export type Permission =
  | "product:read" | "product:write" | "license:read" | "license:create"
  | "license:manage" | "license:revoke" | "activation:issue" | "audit:read"
  | "system:admin";

export interface Identity {
  subject: string;
  role: Role;
  permissions: Permission[];
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ApiClientOptions {
  baseUrl?: string;
  getToken: () => string | null;
  fetchImpl?: FetchLike;
}

export class AdminApi {
  private readonly baseUrl: string;
  private readonly getToken: () => string | null;
  private readonly fetchImpl: FetchLike;

  constructor(opts: ApiClientOptions) {
    this.baseUrl = opts.baseUrl ?? "";
    this.getToken = opts.getToken;
    this.fetchImpl =
      opts.fetchImpl ?? ((input, init) => fetch(input, init));
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const token = this.getToken();
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 204) return undefined as T;
    let payload: unknown = null;
    try {
      payload = await res.json();
    } catch {
      /* empty */
    }
    if (!res.ok) {
      const err = (payload as { error?: { code?: string; message?: string } })?.error;
      throw new ApiError(res.status, err?.code ?? "ERROR", err?.message ?? `HTTP ${res.status}`);
    }
    return payload as T;
  }

  // Identity: who the caller is and what they may do. Also used as the auth
  // probe by the login form (works for every role, unlike a permissioned read).
  me(): Promise<Identity> {
    return this.request("GET", "/api/v1/admin/me");
  }

  listProducts(): Promise<{ items: Product[] }> {
    return this.request("GET", "/api/v1/admin/products");
  }
  createProduct(input: { key: string; name: string; trial?: Partial<TrialPolicy> }): Promise<Product> {
    return this.request("POST", "/api/v1/admin/products", input);
  }

  listLicenses(query: Record<string, string> = {}): Promise<{ items: License[]; total: number }> {
    const qs = new URLSearchParams(query).toString();
    return this.request("GET", `/api/v1/admin/licenses${qs ? `?${qs}` : ""}`);
  }
  getLicense(id: string): Promise<LicenseDetail> {
    return this.request("GET", `/api/v1/admin/licenses/${id}`);
  }
  createLicense(input: CreateLicenseInput): Promise<License> {
    return this.request("POST", "/api/v1/admin/licenses", input);
  }
  generateCode(id: string, maxActivations: number): Promise<{ activationCode: string; activationCodeId: string }> {
    return this.request("POST", `/api/v1/admin/licenses/${id}/activation-codes`, { maxActivations });
  }
  revoke(id: string, reason: string): Promise<void> {
    return this.request("POST", `/api/v1/admin/licenses/${id}/revoke`, { reason });
  }
  suspend(id: string, reason: string): Promise<License> {
    return this.request("POST", `/api/v1/admin/licenses/${id}/suspend`, { reason });
  }
  resume(id: string): Promise<License> {
    return this.request("POST", `/api/v1/admin/licenses/${id}/resume`, {});
  }
  renew(id: string, expiresAt: number | null): Promise<License> {
    return this.request("POST", `/api/v1/admin/licenses/${id}/renew`, { expiresAt });
  }
  listAudit(licenseId?: string): Promise<{ items: AuditEvent[] }> {
    const qs = licenseId ? `?licenseId=${encodeURIComponent(licenseId)}` : "";
    return this.request("GET", `/api/v1/admin/audit${qs}`);
  }
}
