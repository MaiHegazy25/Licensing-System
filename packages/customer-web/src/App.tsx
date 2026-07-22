import { useAuth } from "./auth";
import { Login } from "./views/Login";
import { Licenses } from "./views/Licenses";

export function App() {
  const { isAuthed, loading, identity, logout } = useAuth();

  if (loading) return <div className="login"><div className="muted">Loading…</div></div>;
  if (!isAuthed) return <Login />;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">Vehiclevo · My Licenses</div>
        <div style={{ flex: 1 }} />
        <span className="role-chip" title={identity?.subject}>{identity?.customerId}</span>
        <button className="link" onClick={logout}>Log out</button>
      </header>
      <main className="content">
        <Licenses />
      </main>
    </div>
  );
}
