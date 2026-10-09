FROM rust:1.95.0-alpine AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && touch src/lib.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /app/target/release/rust-auth-sts /usr/local/bin/rust-auth-sts

USER 65532:65532
EXPOSE 8080

ENV BIND_ADDR=0.0.0.0:8080 \
    KEYS_DIR=/app/keys \
    CLIENTS_PATH=/app/config/clients.json

ENTRYPOINT ["/usr/local/bin/rust-auth-sts"]
