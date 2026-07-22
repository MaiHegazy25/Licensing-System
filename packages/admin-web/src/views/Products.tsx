import { useEffect, useState } from "react";
import { useAuth } from "../auth";
import type { Product } from "../api";
import { fmtDate } from "../util";

export function Products() {
  const { api, can } = useAuth();
  const [products, setProducts] = useState<Product[]>([]);
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      setProducts((await api.listProducts()).items);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    void refresh();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.createProduct({ key: key.trim(), name: name.trim() });
      setKey("");
      setName("");
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="panel">
      <h2>Products</h2>
      {can("product:write") && (
        <form className="row form" onSubmit={create}>
          <input placeholder="key (e.g. vv-analyzer)" value={key} onChange={(e) => setKey(e.target.value)} />
          <input placeholder="Display name" value={name} onChange={(e) => setName(e.target.value)} />
          <button className="primary" disabled={!key || !name}>
            Add product
          </button>
        </form>
      )}
      {error && <div className="error">{error}</div>}
      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>Name</th>
            <th>ID</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {products.map((p) => (
            <tr key={p.id}>
              <td>{p.key}</td>
              <td>{p.name}</td>
              <td className="mono">{p.id}</td>
              <td>{fmtDate(p.createdAt)}</td>
            </tr>
          ))}
          {products.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                No products yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
