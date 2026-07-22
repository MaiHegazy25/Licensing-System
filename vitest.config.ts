import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const r = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  test: {
    include: ["packages/**/*.test.ts"],
  },
  resolve: {
    // Resolve workspace packages to their TypeScript source so tests run without
    // a build step. Production consumers use the compiled dist/ entrypoints.
    alias: {
      "@vehiclevo/licensing-shared": r("./packages/shared/src/index.ts"),
      "@vehiclevo/licensing-sdk": r("./packages/sdk/src/index.ts"),
      "@vehiclevo/licensing-server": r("./packages/server/src/index.ts"),
    },
  },
});
