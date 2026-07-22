/**
 * Builds the SigningKeyProvider from configuration. Async because the KMS
 * provider fetches public keys at startup.
 *
 *   SIGNING_PROVIDER=local  -> LocalKeyProvider (dev; keys on disk)
 *   SIGNING_PROVIDER=kms    -> KMS provider (production; keys in a vault/HSM)
 *
 * KMS env (Azure Key Vault reference implementation):
 *   KMS_PROVIDER=azure
 *   AZURE_KEY_VAULT_URL=https://<vault>.vault.azure.net
 *   KMS_KEYS={"key-2026-01":{"name":"licensing-signing","version":"<ver>"}}
 *   ACTIVE_SIGNING_KEY_ID=key-2026-01
 *   AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET   (client credentials)
 */
import type { AppConfig } from "../../config.js";
import type { SigningKeyProvider } from "./key-provider.js";
import { LocalKeyProvider } from "./local-key-provider.js";
import { KmsSigningKeyProvider } from "./kms/kms-signing-key-provider.js";
import {
  AzureKeyVaultSignerClient,
  azureClientCredentialToken,
  type AzureKeyRef,
} from "./kms/azure-key-vault-client.js";

function reqEnv(env: NodeJS.ProcessEnv, key: string): string {
  const v = env[key];
  if (!v) throw new Error(`missing required config: ${key}`);
  return v;
}

export async function buildKeyProvider(
  cfg: AppConfig,
  env: NodeJS.ProcessEnv = process.env,
): Promise<SigningKeyProvider> {
  if (cfg.signingProvider === "local") {
    return LocalKeyProvider.fromDirectory(cfg.localKeysDir, cfg.activeSigningKeyId);
  }
  if (cfg.signingProvider === "kms") {
    const provider = (env.KMS_PROVIDER ?? "azure").toLowerCase();
    if (provider !== "azure") {
      throw new Error(`unsupported KMS_PROVIDER '${provider}' (only 'azure' implemented)`);
    }
    const keys = JSON.parse(reqEnv(env, "KMS_KEYS")) as Record<string, AzureKeyRef>;
    const client = new AzureKeyVaultSignerClient({
      vaultUrl: reqEnv(env, "AZURE_KEY_VAULT_URL"),
      keys,
      getAccessToken: azureClientCredentialToken({
        tenantId: reqEnv(env, "AZURE_TENANT_ID"),
        clientId: reqEnv(env, "AZURE_CLIENT_ID"),
        clientSecret: reqEnv(env, "AZURE_CLIENT_SECRET"),
      }),
    });
    return KmsSigningKeyProvider.create(client, cfg.activeSigningKeyId);
  }
  throw new Error(`unknown SIGNING_PROVIDER '${cfg.signingProvider}'`);
}
