FROM rust:1.75 as builder
WORKDIR /usr/src/noirnet
COPY . .
RUN cargo build --release --bin noirnet-node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/noirnet/target/release/noirnet-node /usr/local/bin/noirnet-node
CMD ["noirnet-node"]
