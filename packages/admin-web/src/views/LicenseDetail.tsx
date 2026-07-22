import { useEffect, useState } from "react";
import { useAuth } from "../auth";
import type { LicenseDetail as Detail } from "../api";
import { fmtDate, toEpochSeconds } from "../util";
import { Modal } from "./Licenses";

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
  const [newCode, setNewCode] = useState<string | null>(null);

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

  async function act(fn: () => Promise<unknown>) {
    setError(null);
    try {
      await fn();
      await refresh();
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (!detail) {
    return (
      <Modal title="License" onClose={onClose}>
        {error ? <div className="error">{error}</div> : <div className="muted">Loading…</div>}
      </Modal>
    );
  }

  const l = detail.license;
  const activeSeats = detail.activations.filter((a) => a.status === "active").length;

  return (
    <Modal title={`License ${l.id.slice(0, 12)}…`} onClose={onClose}>
      <div className="detail">
        <div className="kv">
          <span>Status</span><b><span className={`badge ${l.status}`}>{l.status}</span></b>
          <span>Customer</span><b>{l.customerId}</b>
          <span>Edition</span><b>{l.edition}</b>
          <span>Type</span><b>{l.licenseType}</b>
          <span>Features</span><b>{l.enabledFeatures.join(", ") || "—"}</b>
          <span>Seats</span><b>{activeSeats} / {l.maximumSeats} in use</b>
          <span>Expires</span><b>{fmtDate(l.expiresAt)}</b>
          <span>Offline until</span><b>{fmtDate(l.offlineUntil)}</b>
        </div>

        {detail.revocation && (
          <div className="error">Revoked: {detail.revocation.reason} ({fmtDate(detail.revocation.revokedAt)})</div>
        )}
        {error && <div className="error">{error}</div>}

        <div className="row wrap actions">
          <GenerateCode onGenerate={async (max) => {
            const res = await api.generateCode(l.id, max);
            setNewCode(res.activationCode);
            await refresh();
          }} />
          {l.status === "active" && (
            <button onClick={() => act(() => api.suspend(l.id, "suspended via portal"))}>Suspend</button>
          )}
          {l.status === "suspended" && (
            <button onClick={() => act(() => api.resume(l.id))}>Resume</button>
          )}
          <RenewButton onRenew={(epoch) => act(() => api.renew(l.id, epoch))} />
          {l.status !== "revoked" && (
            <button className="danger" onClick={() => {
              if (confirm("Revoke this license? This is permanent.")) act(() => api.revoke(l.id, "revoked via portal"));
            }}>Revoke</button>
          )}
        </div>

        {newCode && (
          <div className="code-banner">
            <div>Activation code (shown once — copy it now):</div>
            <code>{newCode}</code>
          </div>
        )}

        <h4>Devices / activations ({activeSeats} active)</h4>
        <table>
          <thead><tr><th>Device</th><th>Label</th><th>Status</th><th>Activated</th><th>Last seen</th></tr></thead>
          <tbody>
            {detail.activations.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.deviceId.slice(0, 16)}…</td>
                <td>{a.deviceLabel ?? "—"}</td>
                <td>{a.status}</td>
                <td>{fmtDate(a.activatedAt)}</td>
                <td>{fmtDate(a.lastSeenAt)}</td>
              </tr>
            ))}
            {detail.activations.length === 0 && <tr><td colSpan={5} className="muted">No devices activated.</td></tr>}
          </tbody>
        </table>

        <h4>Activation codes</h4>
        <table>
          <thead><tr><th>ID</th><th>Status</th><th>Used</th><th>Created</th></tr></thead>
          <tbody>
            {detail.activationCodes.map((c) => (
              <tr key={c.id}>
                <td className="mono">{c.id.slice(0, 12)}…</td>
                <td>{c.status}</td>
                <td>{c.usedActivations}/{c.maxActivations}</td>
                <td>{fmtDate(c.createdAt)}</td>
              </tr>
            ))}
            {detail.activationCodes.length === 0 && <tr><td colSpan={4} className="muted">None.</td></tr>}
          </tbody>
        </table>

        <h4>Recent audit</h4>
        <ul className="audit">
          {detail.audit.slice(0, 10).map((e) => (
            <li key={e.id}><span className="mono">{fmtDate(e.at)}</span> · {e.type} · <span className="muted">{e.actor}</span></li>
          ))}
        </ul>
      </div>
    </Modal>
  );
}

function GenerateCode({ onGenerate }: { onGenerate: (max: number) => Promise<void> }) {
  const [max, setMax] = useState(1);
  return (
    <span className="inline">
      <input type="number" min={1} value={max} onChange={(e) => setMax(Number(e.target.value))} style={{ width: 60 }} />
      <button className="primary" onClick={() => void onGenerate(max)}>Generate code</button>
    </span>
  );
}

function RenewButton({ onRenew }: { onRenew: (epoch: number | null) => void }) {
  const [when, setWhen] = useState("");
  return (
    <span className="inline">
      <input type="datetime-local" value={when} onChange={(e) => setWhen(e.target.value)} />
      <button onClick={() => onRenew(when ? toEpochSeconds(when) : null)} disabled={!when}>Renew</button>
    </span>
  );
}
