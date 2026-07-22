/**
 * DEV ONLY: generate a local Ed25519 signing keypair for the `local` signing
 * provider. Writes  <dir>/<kid>.public.pem  and  <dir>/<kid>.private.pem.
 *
 * The private key is DEV material — the output directory is gitignored and must
 * never be committed. Production keys are created and held in KMS/HSM.
 *
 * Usage: node --loader ts-node/esm packages/server/scripts/keygen.ts <kid> [dir]
 *   e.g. keygen key-2026-01 ./keys/local
 */
import { mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { generateEd25519KeyPair } from "@vehiclevo/licensing-shared";

const kid = process.argv[2];
const dir = process.argv[3] ?? "./keys/local";

if (!kid) {
  console.error("usage: keygen <kid> [dir]");
  process.exit(1);
}

mkdirSync(dir, { recursive: true });
const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();

const pubPath = join(dir, `${kid}.public.pem`);
const privPath = join(dir, `${kid}.private.pem`);
writeFileSync(pubPath, publicKeyPem);
writeFileSync(privPath, privateKeyPem, { mode: 0o600 });
chmodSync(privPath, 0o600);

console.log(`wrote ${pubPath}`);
console.log(`wrote ${privPath} (mode 0600, DEV ONLY — do not commit)`);
console.log(`set ACTIVE_SIGNING_KEY_ID=${kid}`);
