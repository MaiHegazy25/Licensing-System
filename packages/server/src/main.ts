import { loadConfig } from "./config.js";
import { buildContainer } from "./container.js";
import { buildHttpServer } from "./api/http.js";
import { runMigrations } from "./infrastructure/persistence/migrate.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const container = buildContainer(config);

  // Apply pending migrations on startup when Postgres-backed. Idempotent and
  // safe for a single-instance deploy; for multi-instance HA run migrations as
  // a separate release step (`npm run migrate`) before rolling instances.
  if (container.pool) {
    const result = await runMigrations(container.pool);
    if (result.applied.length) {
      // eslint-disable-next-line no-console
      console.log("migrations applied:", result.applied.join(", "));
    }
  }

  const app = buildHttpServer(container);

  const shutdown = async () => {
    await app.close();
    await container.close();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  await app.listen({ port: config.httpPort, host: "0.0.0.0" });
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("failed to start:", err instanceof Error ? err.message : err);
  process.exit(1);
});
