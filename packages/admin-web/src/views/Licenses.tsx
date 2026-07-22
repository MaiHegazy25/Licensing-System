import { useEffect, useState } from "react";
import { useAuth } from "../auth";
import type { License, LicenseType, Product } from "../api";
import { fmtDate, toEpochSeconds } from "../util";
import { LicenseDetail } from "./LicenseDetail";

const LICENSE_TYPES: LicenseType[] = [
  "subscription", "perpetual", "trial", "named_user", "device", "floating",
];

export function Licenses() {
  const { api, can } = useAuth();
  const [products, setProducts] = useState<Product[]>([]);
  const [licenses, setLicenses] = useState<License[]>([]);
  const [statusFilter, setStatusFilter] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const q: Record<string, string> = {};
      if (statusFilter) q.status = statusFilter;
      const [lic, prod] = await Promise.all([api.listLicenses(q), api.listProducts()]);
      setLicenses(lic.items);
      setProducts(prod.items);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    void refresh();
  }, [statusFilter]);

  return (
    <div className="panel">
      <div className="row spread">
        <h2>Licenses</h2>
        <div className="row">
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">All statuses</option>
            <option value="active">active</option>
            <option value="suspended">suspended</option>
            <option value="expired">expired</option>
            <option value="revoked">revoked</option>
          </select>
          {can("license:create") && (
            <button className="primary" onClick={() => setCreating(true)} disabled={products.length === 0}>
              New license
            </button>
          )}
        </div>
      </div>
      {products.length === 0 && <div className="muted">Create a product first.</div>}
      {error && <div className="error">{error}</div>}

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Customer</th>
            <th>Edition</th>
            <th>Type</th>
            <th>Seats</th>
            <th>Status</th>
            <th>Expires</th>
          </tr>
        </thead>
        <tbody>
          {licenses.map((l) => (
            <tr key={l.id} className="clickable" onClick={() => setSelected(l.id)}>
              <td className="mono">{l.id.slice(0, 12)}…</td>
              <td>{l.customerId}</td>
              <td>{l.edition}</td>
              <td>{l.licenseType}</td>
              <td>{l.maximumSeats}</td>
              <td>
                <span className={`badge ${l.status}`}>{l.status}</span>
              </td>
              <td>{fmtDate(l.expiresAt)}</td>
            </tr>
          ))}
          {licenses.length === 0 && (
            <tr>
              <td colSpan={7} className="muted">
                No licenses match.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {creating && (
        <CreateLicense
          products={products}
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            void refresh();
          }}
        />
      )}
      {selected && (
        <LicenseDetail
          licenseId={selected}
          onClose={() => setSelected(null)}
          onChanged={() => void refresh()}
        />
      )}
    </div>
  );
}

function CreateLicense({
  products,
  onClose,
  onCreated,
}: {
  products: Product[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { api } = useAuth();
  const [customerId, setCustomerId] = useState("");
  const [productId, setProductId] = useState(products[0]?.id ?? "");
  const [edition, setEdition] = useState("pro");
  const [features, setFeatures] = useState("");
  const [licenseType, setLicenseType] = useState<LicenseType>("subscription");
  const [maximumSeats, setMaximumSeats] = useState(1);
  const [expiresAt, setExpiresAt] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.createLicense({
        customerId: customerId.trim(),
        productId,
        edition: edition.trim(),
        enabledFeatures: features.split(",").map((s) => s.trim()).filter(Boolean),
        licenseType,
        maximumSeats: Number(maximumSeats),
        expiresAt: expiresAt ? toEpochSeconds(expiresAt) : null,
      });
      onCreated();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <Modal title="Create license" onClose={onClose}>
      <form className="grid form" onSubmit={submit}>
        <label>Customer ID<input value={customerId} onChange={(e) => setCustomerId(e.target.value)} required /></label>
        <label>
          Product
          <select value={productId} onChange={(e) => setProductId(e.target.value)}>
            {products.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </label>
        <label>Edition<input value={edition} onChange={(e) => setEdition(e.target.value)} /></label>
        <label>
          Type
          <select value={licenseType} onChange={(e) => setLicenseType(e.target.value as LicenseType)}>
            {LICENSE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label>Features (comma-separated)<input value={features} onChange={(e) => setFeatures(e.target.value)} placeholder="export_pdf, batch_mode" /></label>
        <label>Max seats<input type="number" min={1} value={maximumSeats} onChange={(e) => setMaximumSeats(Number(e.target.value))} /></label>
        <label>Expires at<input type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} /></label>
        {error && <div className="error span2">{error}</div>}
        <div className="row span2">
          <button className="primary" type="submit">Create</button>
          <button type="button" className="link" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Modal>
  );
}

export function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="row spread">
          <h3>{title}</h3>
          <button className="link" onClick={onClose}>✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}
