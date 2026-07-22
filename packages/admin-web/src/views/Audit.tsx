import { useEffect, useState } from "react";
import { useAuth } from "../auth";
import type { AuditEvent } from "../api";
import { fmtDate } from "../util";

export function AuditLog() {
  const { api } = useAuth();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      setEvents((await api.listAudit(filter.trim() || undefined)).items);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    void refresh();
  }, []);

  function exportCsv() {
    const header = ["at", "type", "licenseId", "actor", "metadata"];
    const rows = events.map((e) => [
      fmtDate(e.at),
      e.type,
      e.licenseId ?? "",
      e.actor,
      JSON.stringify(e.metadata).replace(/"/g, "'"),
    ]);
    const csv = [header, ...rows].map((r) => r.map((c) => `"${c}"`).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="panel">
      <div className="row spread">
        <h2>Audit log</h2>
        <div className="row">
          <input placeholder="Filter by license ID" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <button onClick={() => void refresh()}>Search</button>
          <button onClick={exportCsv} disabled={events.length === 0}>Export CSV</button>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      <table>
        <thead>
          <tr><th>Time</th><th>Type</th><th>License</th><th>Actor</th></tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td className="mono">{fmtDate(e.at)}</td>
              <td>{e.type}</td>
              <td className="mono">{e.licenseId?.slice(0, 12) ?? "—"}</td>
              <td>{e.actor}</td>
            </tr>
          ))}
          {events.length === 0 && <tr><td colSpan={4} className="muted">No events.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
