import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { AdminApi, type Identity, type Permission } from "./api";

const TOKEN_KEY = "vv_admin_key";

interface AuthState {
  api: AdminApi;
  isAuthed: boolean;
  loading: boolean;
  identity: Identity | null;
  /** Mirrors the server permission matrix to hide controls (never the enforcer). */
  can: (permission: Permission) => boolean;
  login: (key: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [loading, setLoading] = useState(true);

  const api = useMemo(
    () => new AdminApi({ getToken: () => sessionStorage.getItem(TOKEN_KEY) }),
    [],
  );

  // Re-hydrate identity on mount/refresh: the admin key persists in
  // sessionStorage but the fetched role/permissions do not. Treat the key as a
  // password — never log it.
  useEffect(() => {
    const key = sessionStorage.getItem(TOKEN_KEY);
    if (!key) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then(setIdentity)
      .catch(() => sessionStorage.removeItem(TOKEN_KEY))
      .finally(() => setLoading(false));
  }, [api]);

  const value: AuthState = {
    api,
    isAuthed: Boolean(identity),
    loading,
    identity,
    can: (permission) => identity?.permissions.includes(permission) ?? false,
    async login(key: string) {
      sessionStorage.setItem(TOKEN_KEY, key);
      try {
        const id = await api.me(); // validates the key AND fetches role/permissions
        setIdentity(id);
      } catch (e) {
        sessionStorage.removeItem(TOKEN_KEY);
        setIdentity(null);
        throw e;
      }
    },
    logout() {
      sessionStorage.removeItem(TOKEN_KEY);
      setIdentity(null);
    },
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
