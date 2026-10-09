FROM rust:1.95.0-alpine AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /app/target/release/demo-service /usr/local/bin/demo-service
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/demo-service"]
