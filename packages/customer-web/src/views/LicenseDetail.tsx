import { useEffect, useState } from "react";
import { useAuth } from "../auth";
import type { LicenseDetail as Detail } from "../api";
import { fmtDate } from "../util";

export function LicenseDetail({
  licenseId,
  onClose,
  onChanged,
}: {
  licenseId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { api } = useAuth();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function refresh() {
    try {
      setDetail(await api.getLicense(licenseId));
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    void refresh();
  }, [licenseId]);

  async function deactivate(activationId: string) {
    if (!confirm("Deactivate this device? It will need to reactivate to use the product.")) return;
    setError(null);
    try {
      await api.deactivateDevice(licenseId, activationId);
      await refresh();
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function requestReset() {
    setError(null);
    try {
      await api.requestReset(licenseId, "Requested from customer portal");
      setNotice("Activation reset requested — our support team will follow up.");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function downloadFile() {
    setError(null);
    try {
      const file = await api.downloadLicenseFile(licenseId);
      const blob = new Blob([JSON.stringify(file, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `license-${licenseId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (!detail) {
    return (
      <div className="overlay" onClick={onClose}>
        <div className="modal" onClick={(e) => e.stopPropagation()}>
          {error ? <div className="error">{error}</div> : <div className="muted">Loading…</div>}
        </div>
      </div>
    );
  }

  const l = detail.license;
  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="row spread">
          <h3>{l.edition} · {l.licenseType}</h3>
          <button className="link" onClick={onClose}>✕</button>
        </div>

        <div className="detail">
          <div className="kv">
            <span>Status</span><b><span className={`badge ${l.status}`}>{l.status}</span></b>
            <span>Features</span><b>{l.enabledFeatures.join(", ") || "—"}</b>
            <span>Seats</span><b>{detail.seatsUsed} / {l.maximumSeats} in use</b>
            <span>Expires</span><b>{fmtDate(l.expiresAt)}</b>
            <span>Maintenance</span><b>{fmtDate(l.maintenanceExpiresAt)}</b>
            <span>Offline until</span><b>{fmtDate(l.offlineUntil)}</b>
          </div>

          {detail.revoked && <div className="error">This license has been revoked. Please contact support.</div>}
          {error && <div className="error">{error}</div>}
          {notice && <div className="code-banner">{notice}</div>}

          <div className="row wrap actions">
            <button className="primary" onClick={downloadFile} disabled={detail.revoked}>Download license file</button>
            <button onClick={requestReset}>Request activation reset</button>
          </div>

          <h4>Your devices ({detail.seatsUsed} active)</h4>
          <table>
            <thead>
              <tr><th>Label</th><th>Device</th><th>Status</th><th>Last seen</th><th></th></tr>
            </thead>
            <tbody>
              {detail.devices.map((d) => (
                <tr key={d.id}>
                  <td>{d.deviceLabel ?? "—"}</td>
                  <td className="mono">{d.deviceId.slice(0, 16)}…</td>
                  <td>{d.status}</td>
                  <td>{fmtDate(d.lastSeenAt)}</td>
                  <td>
                    {d.status === "active" && (
                      <button className="danger" onClick={() => deactivate(d.id)}>Deactivate</button>
                    )}
                  </td>
                </tr>
              ))}
              {detail.devices.length === 0 && <tr><td colSpan={5} className="muted">No devices registered.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
