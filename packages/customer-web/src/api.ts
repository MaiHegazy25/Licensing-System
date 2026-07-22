/**
 * Typed customer-portal API client. Framework-agnostic + injectable (fetch +
 * token getter) for testing. Sends the customer token as a Bearer credential;
 * the server scopes every response to that customer.
 */
export type LicenseStatus = "draft" | "active" | "suspended" | "expired" | "revoked";

export interface License {
  id: string;
  customerId: string;
  productId: string;
  edition: string;
  enabledFeatures: string[];
  licenseType: string;
  status: LicenseStatus;
  maximumSeats: number;
  expiresAt: number | null;
  maintenanceExpiresAt: number | null;
  offlineUntil: number | null;
}

export interface Device {
  id: string;
  deviceId: string;
  deviceLabel: string | null;
  status: "active" | "deactivated";
  activatedAt: number;
  lastSeenAt: number;
}

export interface LicenseDetail {
  license: License;
  seatsUsed: number;
  devices: Device[];
  revoked: boolean;
}

export interface Identity {
  customerId: string;
  subject: string;
}

export class ApiError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class CustomerApi {
  private readonly baseUrl: string;
  private readonly getToken: () => string | null;
  private readonly fetchImpl: FetchLike;

  constructor(opts: { baseUrl?: string; getToken: () => string | null; fetchImpl?: FetchLike }) {
    this.baseUrl = opts.baseUrl ?? "";
    this.getToken = opts.getToken;
    this.fetchImpl = opts.fetchImpl ?? ((i, init) => fetch(i, init));
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

  me(): Promise<Identity> {
    return this.request("GET", "/api/v1/customer/me");
  }
  listLicenses(): Promise<{ items: License[] }> {
    return this.request("GET", "/api/v1/customer/licenses");
  }
  getLicense(id: string): Promise<LicenseDetail> {
    return this.request("GET", `/api/v1/customer/licenses/${id}`);
  }
  deactivateDevice(licenseId: string, activationId: string): Promise<void> {
    return this.request(
      "POST",
      `/api/v1/customer/licenses/${licenseId}/devices/${activationId}/deactivate`,
    );
  }
  requestReset(licenseId: string, note: string): Promise<{ status: string }> {
    return this.request("POST", `/api/v1/customer/licenses/${licenseId}/activation-reset`, { note });
  }
  downloadLicenseFile(licenseId: string): Promise<{ token: string; licenseId: string }> {
    return this.request("GET", `/api/v1/customer/licenses/${licenseId}/license-file`);
  }
}
