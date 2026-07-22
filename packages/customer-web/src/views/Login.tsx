import { useState } from "react";
import { useAuth } from "../auth";

export function Login() {
  const { login } = useAuth();
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(key.trim());
    } catch {
      setError("Invalid access key or server unreachable.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <h1>My Licenses</h1>
        <p className="muted">Sign in to view and manage your Vehiclevo licenses.</p>
        <input
          type="password"
          placeholder="Access key"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          autoFocus
        />
        {error && <div className="error">{error}</div>}
        <button className="primary" disabled={busy || key.length === 0}>
          {busy ? "Checking…" : "Sign in"}
        </button>
        <p className="muted small">Production sign-in uses your organization's identity provider.</p>
      </form>
    </div>
  );
}
