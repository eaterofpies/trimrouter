# =========================================================================
# Stage 1: Build & Test Environment (pinned base image & kernel package)
# =========================================================================
FROM rust:1.97.1-slim-trixie AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Pin kernel package version and install build/test prerequisites from devcontainer
ARG KERNEL_PACKAGE_VERSION="6.12.94-1"

# Accept Git commit SHA and build metadata via build arguments
ARG VERGEN_GIT_SHA="unknown"
ARG VERGEN_GIT_COMMIT_DATE=""
ARG VERGEN_BUILD_TIMESTAMP=""

# Export build metadata environment variables for vergen
ENV VERGEN_GIT_SHA=${VERGEN_GIT_SHA}
ENV VERGEN_GIT_COMMIT_DATE=${VERGEN_GIT_COMMIT_DATE}
ENV VERGEN_BUILD_TIMESTAMP=${VERGEN_BUILD_TIMESTAMP}

RUN apt-get update \
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
    linux-image-amd64=${KERNEL_PACKAGE_VERSION} \
    make \
    mtools \
    ovmf \
    parted \
    qemu-system-arm \
    qemu-system-x86 \
    ssh \
    sudo \
    systemd-boot-efi \
    vim \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install target architecture toolchains
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build

# Copy project sources, tests, scripts, and configuration
COPY Cargo.toml Cargo.lock build.rs Makefile ./
COPY scripts/ ./scripts/
COPY config/ ./config/
COPY src/ ./src/
COPY tests/ ./tests/

# 1. Run automated integration tests inside unprivileged micro-QEMU VM
RUN make test-x86_64

# 2. Build the production UEFI disk image from scratch
RUN make target/x86_64/trimrouter.img

# 3. Compress the final raw disk image with xz
RUN xz -9 -k target/x86_64/trimrouter.img

# =========================================================================
# Stage 2: Minimal Scratch Image Output
# =========================================================================
FROM scratch

COPY --from=builder /build/target/x86_64/trimrouter.img.xz /trimrouter.img.xz
