# syntax=docker/dockerfile:1.7
# Multi-stage build for the CISO Dashboard API.
ARG NODE_IMAGE=node:22-alpine

# ---- 1. Build: compile TypeScript & generate Prisma client -------------------
FROM ${NODE_IMAGE} AS build
RUN apk add --no-cache openssl
WORKDIR /app
COPY package.json package-lock.json ./
# Lifecycle scripts disabled (supply-chain hardening); Prisma engines fetched explicitly.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY prisma ./prisma
COPY src ./src
RUN npx prisma generate && npx tsc -p tsconfig.build.json

# ---- 2. Production dependencies only -----------------------------------------
FROM ${NODE_IMAGE} AS prod-deps
RUN apk add --no-cache openssl
WORKDIR /app
ENV CHECKPOINT_DISABLE=1
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && npm rebuild prisma @prisma/engines \
 && npm cache clean --force
COPY prisma ./prisma
RUN npx prisma generate

# ---- 3. Runtime: minimal, non-root, read-only friendly -----------------------
FROM ${NODE_IMAGE} AS runtime
RUN apk upgrade --no-cache && apk add --no-cache tini openssl \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /usr/local/lib/node_modules/corepack
ENV NODE_ENV=production \
    CHECKPOINT_DISABLE=1 \
    PRISMA_HIDE_UPDATE_MESSAGE=1 \
    NODE_OPTIONS="--disable-proto=delete --max-http-header-size=16384"
WORKDIR /app
COPY --from=prod-deps --chown=root:root /app/node_modules ./node_modules
COPY --from=build --chown=root:root /app/dist ./dist
COPY --chown=root:root prisma ./prisma
COPY --chown=root:root package.json ./
USER node
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["node", "dist/healthcheck.js"]
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/index.js"]
