# syntax=docker/dockerfile:1.7
#
# Build context: the parent directory with server/ and common/ side by side
# (the same layout as locally; CI checks both out like that):
#
#   docker build -f server/Dockerfile -t nyapassword-server .
#
# Rust is cross-compiled on the build machine with cargo-zigbuild (static musl
# binaries for amd64 and arm64), so multi-arch images need no emulation.

FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /src/common/web
COPY common/web/package.json common/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY common/web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS build
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends python3-pip && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages ziglang==0.13.0 \
    && cargo install cargo-zigbuild --locked \
    && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
WORKDIR /src
COPY common/ common/
COPY server/ server/
COPY --from=web /src/common/web/dist/ server/webdist/
WORKDIR /src/server
RUN case "$TARGETARCH" in \
        amd64) T=x86_64-unknown-linux-musl ;; \
        arm64) T=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && cargo zigbuild --release --locked --target "$T" \
    && cp "../target/$T/release/nyapassword-server" /nyapassword-server

FROM alpine:3.22
RUN apk add --no-cache su-exec tzdata ca-certificates \
    && adduser -D -H -u 10001 nyapassword
COPY --from=build /nyapassword-server /usr/local/bin/nyapassword-server
COPY server/deploy/docker/entrypoint.sh /entrypoint.sh
ENV NYAPASSWORD_DATA=/data \
    NYAPASSWORD_LISTEN=0.0.0.0:8087
VOLUME /data
EXPOSE 8087
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["nyapassword-server", "--healthcheck"]
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nyapassword-server"]
