# bb daemon image — loopback-safe defaults; mount a data volume.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml rust-toolchain.toml ./
COPY src ./src
COPY migrations ./migrations
COPY web ./web
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/bb /usr/local/bin/bb
ENV BB_DATA_DIR=/data
VOLUME /data
EXPOSE 17890 17891
ENTRYPOINT ["bb"]
CMD ["serve", "--data-dir", "/data", "--foreground"]
