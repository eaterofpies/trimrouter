#!/bin/bash
# =========================================================================
# Generic Kernel Downloader & Extractor (Supports all architectures)
# =========================================================================
set -e

ARCH=$1
if [ -z "$ARCH" ]; then
    echo "Usage: $0 <arch>"
    exit 1
fi

case "$ARCH" in
    x86_64)
        DEB_ARCH="amd64"
        KERNEL_PKG="linux-image-amd64"
        ;;
    arm64)
        DEB_ARCH="arm64"
        KERNEL_PKG="linux-image-arm64"
        ;;
    armhf)
        DEB_ARCH="armhf"
        KERNEL_PKG="linux-image-armmp"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

CURDIR=$(pwd)
TEST_BOOT="target/${ARCH}/test_boot"
APT_DIR="target/${ARCH}/apt"

echo "[apt-test] Downloading generic ${ARCH} kernel package..."
rm -rf "$TEST_BOOT" "$APT_DIR"
mkdir -p "$TEST_BOOT"
mkdir -p "$APT_DIR/etc/apt/trusted.gpg.d"
mkdir -p "$APT_DIR/var/lib/apt/lists/partial"
mkdir -p "$APT_DIR/var/cache/apt/archives/partial"
touch "$APT_DIR/var/lib/apt/status"

# Copy host keyring for Debian verification
cp /usr/share/keyrings/debian-archive-keyring.gpg "$APT_DIR/etc/apt/trusted.gpg.d/debian.gpg"

echo "deb [arch=${DEB_ARCH}] http://deb.debian.org/debian/ trixie main" > "$APT_DIR/etc/apt/sources.list"

APT_OPTS="-o Dir=${CURDIR}/${APT_DIR} -o Dir::Etc::main=/dev/null -o Dir::Etc::parts=/dev/null"

echo "Updating sandboxed ${ARCH} APT package index..."
apt-get ${APT_OPTS} update

echo "Resolving dependencies for meta-package: ${KERNEL_PKG}..."
PKG=$(apt-cache ${APT_OPTS} show "${KERNEL_PKG}" | grep Depends | head -n 1 | awk '{print $2}' | tr -d ',')
echo "Downloading resolved package: ${PKG}..."

cd "$TEST_BOOT"
apt-get ${APT_OPTS} download "${PKG}"

echo "Extracting generic ${ARCH} kernel package..."
for f in *.deb; do
    ar x "$f"
    if [ -f data.tar.xz ]; then
        tar -xf data.tar.xz 2>/dev/null
    elif [ -f data.tar.zst ]; then
        tar -xf data.tar.zst 2>/dev/null
    elif [ -f data.tar.gz ]; then
        tar -xf data.tar.gz 2>/dev/null
    fi
    rm -f debian-binary control.tar.* data.tar.*
done

echo "Locating and copying kernel image..."
cp boot/vmlinuz-* ./vmlinuz

# Support usr-merged directory layout in trixie release
if [ -d usr/lib ] && [ ! -d lib ]; then
    ln -s usr/lib lib
fi

KVER=$(ls lib/modules 2>/dev/null | head -n 1)
if [ -n "$KVER" ]; then
    echo "Generating kernel module dependency database for $KVER..."
    depmod -b "${CURDIR}/${TEST_BOOT}" "$KVER"
fi

touch .kernel_extracted
