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
      setError("Invalid admin key or server unreachable.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <h1>Licensing Admin</h1>
        <p className="muted">Enter your admin API key to continue.</p>
        <input
          type="password"
          placeholder="Admin API key"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          autoFocus
        />
        {error && <div className="error">{error}</div>}
        <button className="primary" disabled={busy || key.length === 0}>
          {busy ? "Checking…" : "Sign in"}
        </button>
        <p className="muted small">
          Production replaces this with SSO (Entra ID / Keycloak) + role-based access.
        </p>
      </form>
    </div>
  );
}
