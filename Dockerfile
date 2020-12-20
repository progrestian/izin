FROM rust:alpine AS builder
WORKDIR /izin
RUN apk add musl-dev && USER=root cargo init .
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release && rm -rf src
COPY src ./src
RUN cargo build --release

FROM alpine
WORKDIR /izin
COPY --from=builder /izin/target/release/cli /izin/target/release/server ./
CMD ["./server"]
