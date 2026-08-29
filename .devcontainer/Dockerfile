FROM rust:1.97.1-slim-trixie

ARG USERNAME=vscode 
ARG USER_UID=1000
ARG USER_GID=$USER_UID

ENV DEBIAN_FRONTEND=noninteractive

# Enable non-free-firmware and install matching kernel + build/test prerequisites for the host architecture
RUN (sed -i 's/Components: main/Components: main non-free-firmware/' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true) \
    && (sed -i 's/main$/main non-free-firmware/' /etc/apt/sources.list 2>/dev/null || true) \
    && apt-get update \
    && case "$(dpkg --print-architecture)" in \
    amd64) KERNEL_PKG="linux-image-amd64" ;; \
    arm64) KERNEL_PKG="linux-image-arm64" ;; \
    armhf) KERNEL_PKG="linux-image-armmp" ;; \
    *) KERNEL_PKG="" ;; \
    esac \
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
    libssl-dev \
    make \
    mtools \
    ovmf \
    parted \
    pkg-config \
    qemu-system-arm \
    qemu-system-x86 \
    raspi-firmware \
    ssh \
    sudo \
    systemd-boot-efi \
    vim \
    xz-utils \
    ${KERNEL_PKG} \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain components, all musl cross targets, and cargo developer tools
RUN rustup component add clippy rustfmt \
    && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl arm-unknown-linux-musleabihf \
    && cargo install cargo-audit cargo-edit --locked

# Create the unprivileged user with sudo permissions
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

USER ${USERNAME}

# Set CARGO_HOME to workspace directory to isolate package caches
ENV CARGO_HOME=/workspaces/rustyrouter/.cargo
ENV PATH="${CARGO_HOME}/bin:${PATH}"

# Setup antigravity CLI and user PATH
RUN curl -fsSL https://antigravity.google/cli/install.sh | bash \
    && echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc