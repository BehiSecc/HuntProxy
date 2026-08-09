FROM rust:1-bookworm AS build
RUN apt-get update \
  && apt-get install -y --no-install-recommends cmake libclang-dev \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY migrations ./migrations
COPY web ./web
COPY browser-worker ./browser-worker
RUN cargo build --release --locked --bin HuntProxy

FROM node:20-bookworm-slim AS browser
WORKDIR /browser-worker
COPY browser-worker/package.json browser-worker/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY browser-worker/index.js ./

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    curl \
    dumb-init \
    fonts-liberation \
    nodejs \
    python3 \
    python3-boto3 \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 10001 huntproxy \
  && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin huntproxy \
  && install -d -o huntproxy -g huntproxy /data /opt/huntproxy/browser-worker

COPY --from=build /src/target/release/HuntProxy /usr/local/bin/HuntProxy
COPY --from=browser --chown=huntproxy:huntproxy /browser-worker /opt/huntproxy/browser-worker

ENV HUNTPROXY_DATA_DIR=/data \
    HUNTPROXY_BROWSER_WORKER_PATH=/opt/huntproxy/browser-worker/index.js \
    HUNTPROXY_PLAYWRIGHT_CORE_PATH=/opt/huntproxy/browser-worker/node_modules/playwright-core \
    HUNTPROXY_CHROME_EXECUTABLE=/usr/bin/chromium

USER huntproxy:huntproxy
VOLUME ["/data"]
EXPOSE 17890 17891 9222
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD curl --fail --silent http://127.0.0.1:17890/api/v1/health >/dev/null || exit 1
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/dumb-init", "--", "HuntProxy"]
CMD ["serve", "--foreground"]
