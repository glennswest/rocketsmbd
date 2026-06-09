# Static musl binary in a scratch image. Build with podman:
#   cargo build --release --target aarch64-unknown-linux-musl
#   podman build -t rocketsmbd -f Containerfile .
FROM scratch
COPY target/aarch64-unknown-linux-musl/release/rocketsmbd /rocketsmbd
ENTRYPOINT ["/rocketsmbd", "--config", "/etc/rocketsmbd/rocketsmbd.toml"]
