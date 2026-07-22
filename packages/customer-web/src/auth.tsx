import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { CustomerApi, type Identity } from "./api";

const TOKEN_KEY = "vv_customer_key";

interface AuthState {
  api: CustomerApi;
  isAuthed: boolean;
  loading: boolean;
  identity: Identity | null;
  login: (key: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [loading, setLoading] = useState(true);

  const api = useMemo(
    () => new CustomerApi({ getToken: () => sessionStorage.getItem(TOKEN_KEY) }),
    [],
  );

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
    async login(key: string) {
      sessionStorage.setItem(TOKEN_KEY, key);
      try {
        setIdentity(await api.me());
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
