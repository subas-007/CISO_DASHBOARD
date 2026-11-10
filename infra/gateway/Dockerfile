# syntax=docker/dockerfile:1.7
# Gateway image: builds the React SPA and serves it from hardened, unprivileged NGINX
# which also terminates TLS 1.3 and reverse-proxies /api (mTLS) and /auth (Keycloak).
# Build context: repository root.

FROM node:22-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.28-alpine AS runtime
USER root
RUN apk upgrade --no-cache && rm -f /etc/nginx/conf.d/default.conf
COPY infra/nginx/nginx.conf /etc/nginx/nginx.conf
COPY infra/nginx/security-headers.conf /etc/nginx/security-headers.conf
COPY infra/nginx/proxy-api.conf /etc/nginx/proxy-api.conf
COPY infra/nginx/proxy-idp.conf /etc/nginx/proxy-idp.conf
COPY --from=build /app/dist /usr/share/nginx/html
RUN chmod -R a=rX /usr/share/nginx/html /etc/nginx
USER 101
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
