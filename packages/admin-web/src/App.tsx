import { useState } from "react";
import { useAuth } from "./auth";
import { Login } from "./views/Login";
import { Products } from "./views/Products";
import { Licenses } from "./views/Licenses";
import { AuditLog } from "./views/Audit";

type Tab = "licenses" | "products" | "audit";

export function App() {
  const { isAuthed, logout } = useAuth();
  const [tab, setTab] = useState<Tab>("licenses");

  if (!isAuthed) return <Login />;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">Vehiclevo Licensing · Admin</div>
        <nav className="tabs">
          <button className={tab === "licenses" ? "active" : ""} onClick={() => setTab("licenses")}>
            Licenses
          </button>
          <button className={tab === "products" ? "active" : ""} onClick={() => setTab("products")}>
            Products
          </button>
          <button className={tab === "audit" ? "active" : ""} onClick={() => setTab("audit")}>
            Audit
          </button>
        </nav>
        <button className="link" onClick={logout}>
          Log out
        </button>
      </header>
      <main className="content">
        {tab === "licenses" && <Licenses />}
        {tab === "products" && <Products />}
        {tab === "audit" && <AuditLog />}
      </main>
    </div>
  );
}
