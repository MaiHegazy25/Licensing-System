/**
 * Configuration loading + validation. The server refuses to start with an
 * invalid/incomplete config (fail fast) rather than booting into an insecure
 * or half-configured state.
 */
export interface AppConfig {
  env: "development" | "staging" | "production";
  httpPort: number;
  signingProvider: "local" | "kms";
  localKeysDir: string;
  activeSigningKeyId: string;
  tokenIssuer: string;
  tokenAudience: string;
  tokenTtlSeconds: number;
  activationCodePepper: string;
  databaseUrl: string | null;
}

class ConfigError extends Error {}

function req(env: NodeJS.ProcessEnv, key: string): string {
  const v = env[key];
  if (v === undefined || v === "") {
    throw new ConfigError(`missing required config: ${key}`);
  }
  return v;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const appEnv = (env.LICENSING_ENV ?? "development") as AppConfig["env"];
  if (!["development", "staging", "production"].includes(appEnv)) {
    throw new ConfigError(`invalid LICENSING_ENV: ${appEnv}`);
  }

  const signingProvider = (env.SIGNING_PROVIDER ?? "local") as "local" | "kms";
  if (!["local", "kms"].includes(signingProvider)) {
    throw new ConfigError(`invalid SIGNING_PROVIDER: ${signingProvider}`);
  }
  if (appEnv === "production" && signingProvider === "local") {
    throw new ConfigError("SIGNING_PROVIDER=local is not allowed in production");
  }

  const cfg: AppConfig = {
    env: appEnv,
    httpPort: Number(env.LICENSING_HTTP_PORT ?? "8080"),
    signingProvider,
    localKeysDir: env.LOCAL_KEYS_DIR ?? "./keys/local",
    activeSigningKeyId: req(env, "ACTIVE_SIGNING_KEY_ID"),
    tokenIssuer: req(env, "TOKEN_ISSUER"),
    tokenAudience: req(env, "TOKEN_AUDIENCE"),
    tokenTtlSeconds: Number(env.TOKEN_TTL_SECONDS ?? "3600"),
    activationCodePepper: req(env, "ACTIVATION_CODE_PEPPER"),
    databaseUrl: env.DATABASE_URL ?? null,
  };

  if (!Number.isInteger(cfg.httpPort) || cfg.httpPort <= 0) {
    throw new ConfigError(`invalid LICENSING_HTTP_PORT: ${env.LICENSING_HTTP_PORT}`);
  }
  if (cfg.activationCodePepper.length < 16) {
    throw new ConfigError("ACTIVATION_CODE_PEPPER must be >= 16 chars");
  }
  // Production hardening: a wildcard CORS origin for the admin/customer SPAs is
  // acceptable only in development — fail fast rather than boot open.
  if (appEnv === "production") {
    const origin = env.ADMIN_WEB_ORIGIN;
    if (!origin || origin === "*") {
      throw new ConfigError(
        "ADMIN_WEB_ORIGIN must be set to an explicit origin (not '*') in production",
      );
    }
  }
  return cfg;
}
