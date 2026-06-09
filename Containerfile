# Static musl binary in a scratch image. Build with podman:
#   cargo build --release --target x86_64-unknown-linux-musl
#   podman build -t rocketsmbd -f Containerfile .
# For ARM64 (MikroTik Rose / Apple Silicon podman machine):
#   cargo build --release --target aarch64-unknown-linux-musl
#   podman build -t rocketsmbd --build-arg TARGET=aarch64-unknown-linux-musl -f Containerfile .
ARG TARGET=x86_64-unknown-linux-musl
FROM scratch
ARG TARGET
COPY target/${TARGET}/release/rocketsmbd /rocketsmbd
ENTRYPOINT ["/rocketsmbd", "--config", "/etc/rocketsmbd/rocketsmbd.toml"]
