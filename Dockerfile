# syntax=docker/dockerfile:1

# renovate: datasource=docker depName=rust
ARG RUST_VERSION="1.97.1-slim-trixie"

# Target architecture: x86_64, arm64, or armhf
ARG ARCH="x86_64"

# =========================================================================
# Stage 1: Build & Test Environment (pinned base image & kernel package)
# =========================================================================
FROM rust:${RUST_VERSION} AS builder

ARG ARCH="x86_64"

# renovate: datasource=repology depName=debian_13/linux
ARG KERNEL_PACKAGE_VERSION="6.12.94-1"

# Accept Git commit SHA and build metadata via build arguments
ARG VERGEN_GIT_SHA="unknown"
ARG VERGEN_GIT_COMMIT_DATE=""
ARG VERGEN_BUILD_TIMESTAMP=""

# Export build metadata environment variables for vergen
ENV VERGEN_GIT_SHA=${VERGEN_GIT_SHA}
ENV VERGEN_GIT_COMMIT_DATE=${VERGEN_GIT_COMMIT_DATE}
ENV VERGEN_BUILD_TIMESTAMP=${VERGEN_BUILD_TIMESTAMP}

ENV DEBIAN_FRONTEND=noninteractive

# Enable non-free-firmware and install kernel matching target architecture
RUN sed -i 's/Components: main/Components: main non-free-firmware/' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true \
  && apt-get update \
  && case "${ARCH}" in \
  x86_64) KERNEL_PKG="linux-image-amd64" ;; \
  arm64)  KERNEL_PKG="linux-image-arm64" ;; \
  armhf)  KERNEL_PKG="linux-image-armmp" ;; \
  *) echo "Unsupported ARCH: ${ARCH}" && exit 1 ;; \
  esac \
  && if [ -n "${KERNEL_PACKAGE_VERSION}" ]; then KERNEL_PKG="${KERNEL_PKG}=${KERNEL_PACKAGE_VERSION}"; fi \
  && apt-get install -y --no-install-recommends \
  bash \
  binutils \
  ca-certificates \
  clang \
  cpio \
  curl \
  erofs-utils \
  git \
  kmod \
  less \
  libclang-dev \
  make \
  mtools \
  ovmf \
  parted \
  qemu-system-arm \
  qemu-system-x86 \
  raspi-firmware \
  ssh \
  sudo \
  systemd-boot-efi \
  vim \
  xz-utils \
  "${KERNEL_PKG}" \
  && rm -rf /var/lib/apt/lists/*

# Install target architecture toolchains
RUN case "${ARCH}" in \
  x86_64) rustup target add x86_64-unknown-linux-musl ;; \
  arm64)  rustup target add aarch64-unknown-linux-musl ;; \
  armhf)  rustup target add arm-unknown-linux-musleabihf ;; \
  esac

WORKDIR /build

# Copy project sources, tests, scripts, and configuration
COPY Cargo.toml Cargo.lock build.rs Makefile ./
COPY scripts/ ./scripts/
COPY config/ ./config/
COPY src/ ./src/
COPY tests/ ./tests/

# 1. Run integration tests (for x86_64) or unit tests
RUN if [ "${ARCH}" = "x86_64" ]; then make test-x86_64; else cargo test --lib; fi

# 2. Build the production disk image from scratch
RUN make target/${ARCH}/trimrouter.img

# 3. Compress the final raw disk image with xz
RUN xz -9 -k target/${ARCH}/trimrouter.img

# =========================================================================
# Stage 2: Minimal Scratch Image Output
# =========================================================================
FROM scratch

ARG ARCH="x86_64"

COPY --from=builder /build/target/${ARCH}/trimrouter.img.xz /trimrouter-${ARCH}.img.xz
