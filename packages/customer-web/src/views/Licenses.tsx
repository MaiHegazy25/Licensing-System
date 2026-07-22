import { useEffect, useState } from "react";
import { useAuth } from "../auth";
import type { License } from "../api";
import { fmtDate } from "../util";
import { LicenseDetail } from "./LicenseDetail";

export function Licenses() {
  const { api } = useAuth();
  const [licenses, setLicenses] = useState<License[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      setLicenses((await api.listLicenses()).items);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    void refresh();
  }, []);

  return (
    <div className="panel">
      <h2>Your licenses</h2>
      {error && <div className="error">{error}</div>}
      <table>
        <thead>
          <tr>
            <th>Edition</th>
            <th>Type</th>
            <th>Features</th>
            <th>Seats</th>
            <th>Status</th>
            <th>Expires</th>
          </tr>
        </thead>
        <tbody>
          {licenses.map((l) => (
            <tr key={l.id} className="clickable" onClick={() => setSelected(l.id)}>
              <td>{l.edition}</td>
              <td>{l.licenseType}</td>
              <td>{l.enabledFeatures.join(", ") || "—"}</td>
              <td>{l.maximumSeats}</td>
              <td><span className={`badge ${l.status}`}>{l.status}</span></td>
              <td>{fmtDate(l.expiresAt)}</td>
            </tr>
          ))}
          {licenses.length === 0 && (
            <tr><td colSpan={6} className="muted">No licenses on file.</td></tr>
          )}
        </tbody>
      </table>
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
