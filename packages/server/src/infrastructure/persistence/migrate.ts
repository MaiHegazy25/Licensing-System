/**
 * Minimal, dependency-free migration runner. Applies `NNN_*.sql` files from the
 * migrations directory in lexical order, each in its own transaction, and
 * records applied versions in `schema_migrations`. Idempotent: already-applied
 * files are skipped, so it is safe to run on every deploy.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool } from "./pool.js";
import { withTransaction } from "./pool.js";

export function defaultMigrationsDir(): string {
  // dist/infrastructure/persistence -> package root /migrations
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "..", "..", "migrations");
}

export interface MigrationResult {
  applied: string[];
  skipped: string[];
}

export async function runMigrations(
  pool: Pool,
  migrationsDir = defaultMigrationsDir(),
): Promise<MigrationResult> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version     TEXT PRIMARY KEY,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  const { rows } = await pool.query<{ version: string }>("SELECT version FROM schema_migrations");
  const done = new Set(rows.map((r) => r.version));

  const applied: string[] = [];
  const skipped: string[] = [];
  for (const file of files) {
    if (done.has(file)) {
      skipped.push(file);
      continue;
    }
    const sql = readFileSync(join(migrationsDir, file), "utf8");
    await withTransaction(pool, async (client) => {
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (version) VALUES ($1)", [file]);
    });
    applied.push(file);
  }
  return { applied, skipped };
}

// CLI entry: `node dist/infrastructure/persistence/migrate.js`
if (import.meta.url === `file://${process.argv[1]}`) {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error("DATABASE_URL is required to run migrations");
    process.exit(1);
  }
  const { createPool } = await import("./pool.js");
  const pool = createPool(url);
  try {
    const result = await runMigrations(pool);
    console.log(`migrations applied: ${result.applied.length}, skipped: ${result.skipped.length}`);
    if (result.applied.length) console.log("  applied:", result.applied.join(", "));
  } finally {
    await pool.end();
  }
}
