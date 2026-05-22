# syntax=docker/dockerfile:1

FROM rust:1-slim AS build

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app
COPY --from=build /app/target/release/wireguard_viz ./wireguard_viz

EXPOSE 3000
CMD ["./wireguard_viz"]
