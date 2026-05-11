FROM rust:1.95.0-alpine AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM alpine:latest AS runtime
WORKDIR /app

RUN apk update \
    && apk add --no-cache ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/rust-auth-sts /usr/local/bin/rust-auth-sts

RUN mkdir -p /app/secrets
EXPOSE 8080

ENV BIND_ADDR=0.0.0.0:8080
ENV JWT_SECRET_FILE=/app/secrets/private_rsa_pkcs8.pem

CMD ["/usr/local/bin/rust-auth-sts"]