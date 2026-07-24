# HuntProxy daemon image — loopback-safe defaults; mount a data volume.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY migrations ./migrations
COPY web ./web
COPY browser-worker ./browser-worker
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/HuntProxy /usr/local/bin/HuntProxy
ENV BB_DATA_DIR=/data
VOLUME /data
EXPOSE 17890 17891
ENTRYPOINT ["HuntProxy"]
CMD ["serve", "--data-dir", "/data", "--foreground"]
