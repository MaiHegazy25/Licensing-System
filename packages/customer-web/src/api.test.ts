import { describe, it, expect, vi } from "vitest";
import { CustomerApi, ApiError } from "./api";

function mockFetch(status: number, body: unknown) {
  return vi.fn(async () =>
    new Response(status === 204 ? null : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    }),
  );
}

describe("CustomerApi", () => {
  it("sends the bearer token and lists licenses", async () => {
    const fetchImpl = mockFetch(200, { items: [{ id: "lic_1" }] });
    const api = new CustomerApi({ getToken: () => "cust-key", fetchImpl, baseUrl: "http://x" });
    const res = await api.listLicenses();
    expect(res.items[0].id).toBe("lic_1");
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toContain("/api/v1/customer/licenses");
    expect((init!.headers as Record<string, string>).authorization).toBe("Bearer cust-key");
  });

  it("throws a typed ApiError (404 isolation) on cross-customer access", async () => {
    const fetchImpl = mockFetch(404, { error: { code: "NOT_FOUND", message: "license not found" } });
    const api = new CustomerApi({ getToken: () => "k", fetchImpl });
    await expect(api.getLicense("someone-elses")).rejects.toBeInstanceOf(ApiError);
    await expect(api.getLicense("someone-elses")).rejects.toMatchObject({ status: 404 });
  });

  it("handles 204 on device deactivation", async () => {
    const fetchImpl = mockFetch(204, null);
    const api = new CustomerApi({ getToken: () => "k", fetchImpl });
    await expect(api.deactivateDevice("lic_1", "act_1")).resolves.toBeUndefined();
  });
});
