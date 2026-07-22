import { loadConfig } from "./config.js";
import { buildContainer } from "./container.js";
import { buildHttpServer } from "./api/http.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const container = buildContainer(config);
  const app = buildHttpServer(container);
  await app.listen({ port: config.httpPort, host: "0.0.0.0" });
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("failed to start:", err instanceof Error ? err.message : err);
  process.exit(1);
});
