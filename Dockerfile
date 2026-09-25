# HypenSec Astra: web app + DPDP consent scanner in one container.
# The Playwright image ships Chromium and its system libraries; its version must match
# the "playwright" version pinned in scanner-service/package.json.
FROM mcr.microsoft.com/playwright:v1.63.0-noble

ENV NODE_ENV=production \
    PORT=8787 \
    HOST=0.0.0.0 \
    AUDIT_LOG=/app/data/audit.log

WORKDIR /app

COPY scanner-service/package.json scanner-service/package-lock.json scanner-service/
RUN cd scanner-service && npm ci --omit=dev --no-audit --no-fund

# Only the files the service serves or runs (see APP_FILES in scanner-service/src/server.js).
COPY index.html terms.html privacy.html grc.js grc.css ./
COPY icons/hypensec-mark.png icons/favicon-64.png icons/
COPY fonts/ fonts/
COPY scanner-service/src/ scanner-service/src/

# Run as the image's unprivileged user; the audit log is the only thing written to disk.
RUN mkdir -p /app/data && chown -R pwuser:pwuser /app/data
USER pwuser

EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/health').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "scanner-service/src/server.js"]
