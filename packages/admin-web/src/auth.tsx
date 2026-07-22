import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { AdminApi } from "./api";

const TOKEN_KEY = "vv_admin_key";

interface AuthState {
  api: AdminApi;
  isAuthed: boolean;
  login: (key: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  // Admin key lives in sessionStorage: cleared when the tab closes and on logout.
  // It is a bearer credential; treat it like a password (do not log it).
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem(TOKEN_KEY));

  const api = useMemo(
    () => new AdminApi({ getToken: () => sessionStorage.getItem(TOKEN_KEY) }),
    [],
  );

  const value: AuthState = {
    api,
    isAuthed: Boolean(token),
    async login(key: string) {
      sessionStorage.setItem(TOKEN_KEY, key);
      try {
        await api.checkAuth(); // validate before we consider it "logged in"
        setToken(key);
      } catch (e) {
        sessionStorage.removeItem(TOKEN_KEY);
        setToken(null);
        throw e;
      }
    },
    logout() {
      sessionStorage.removeItem(TOKEN_KEY);
      setToken(null);
    },
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
