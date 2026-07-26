# Production image for the licensing server (packages/server).
# The SPAs (admin-web/customer-web) are static bundles deployed separately.
#
# Build:  docker build -t licensing-server .
# Run:    see docs/deployment.md for the full environment checklist.

# ---- build stage: compile TypeScript (composite build) ----
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/server ./packages/server
COPY packages/sdk ./packages/sdk
# --include-workspace-root pulls the root devDependencies (typescript, @types/node)
# that the composite build needs; the SPA workspaces are not copied or installed.
RUN npm ci --include-workspace-root \
      --workspace @vehiclevo/licensing-shared \
      --workspace @vehiclevo/licensing-server \
      --workspace @vehiclevo/licensing-sdk \
 && npx tsc --build

# ---- runtime stage: production deps + compiled output only ----
FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
# Root manifests + the two workspaces the server needs; npm resolves the
# @vehiclevo/licensing-shared workspace symlink from these.
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/server/package.json packages/server/
RUN npm ci --omit=dev -w @vehiclevo/licensing-server --ignore-scripts \
 && npm cache clean --force
COPY --from=build /app/packages/shared/dist packages/shared/dist
COPY --from=build /app/packages/server/dist packages/server/dist
# Migrations MUST ship in the image — the runner resolves them relative to dist/.
COPY packages/server/migrations packages/server/migrations

# Run as the non-root user provided by the base image.
USER node
EXPOSE 8080
# TLS terminates in front of this container (gateway/ingress).
CMD ["node", "packages/server/dist/main.js"]
