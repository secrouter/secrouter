# syntax=docker/dockerfile:1
# SecRouter — multi-stage build. Config is mounted at runtime (env-specific),
# never baked into the image.

# ---- build: compile TS → dist/ ----
FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ---- runtime: prod deps + dist only, non-root ----
FROM node:24-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
# Writable data dir for the node:sqlite store (audit + usage ledger).
RUN mkdir -p /var/lib/secrouter && chown -R node:node /var/lib/secrouter
USER node
EXPOSE 18800
# Liveness: hit /health (unauthenticated). Uses the Node global fetch (>=18).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.SECROUTER_PORT||18800)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/server.js"]
