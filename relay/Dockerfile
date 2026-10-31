# Clipway relay: small image, no shell, non-root user, nothing written to disk.
# Build context: this folder.
#   docker build -t clipway-relay relay
#   docker run --rm -p 7710:7710 --read-only --cap-drop ALL --security-opt no-new-privileges clipway-relay

FROM node:22.23-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM gcr.io/distroless/nodejs22-debian12:nonroot
ENV NODE_ENV=production \
    PORT=7710
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json server.js crypto.js bip39-english.js ./
USER nonroot
EXPOSE 7710
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:7710/health').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["server.js"]
