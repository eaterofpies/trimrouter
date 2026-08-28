#!/bin/bash
# =========================================================================
# Generic Kernel Stager (Supports native container kernel & cross-arch Debian)
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
        HOST_ARCH="x86_64"
        KERNEL_PKG="linux-image-amd64"
        ;;
    arm64)
        DEB_ARCH="arm64"
        HOST_ARCH="aarch64"
        KERNEL_PKG="linux-image-arm64"
        ;;
    armhf)
        DEB_ARCH="armhf"
        HOST_ARCH="armv7l"
        KERNEL_PKG="linux-image-armmp"
        ;;
    *)
        echo "[kernel-extract] ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

CURDIR=$(pwd)
TEST_BOOT="target/${ARCH}/test_boot"
APT_DIR="target/${ARCH}/apt"
CURRENT_UNAME_M=$(uname -m)

# 1. Native Build: Use local container kernel if building for native architecture
INSTALLED_VMLINUZ=$(ls -1 /boot/vmlinuz-* 2>/dev/null | head -n 1 || true)
if [ "$CURRENT_UNAME_M" = "$HOST_ARCH" ] && [ -n "$INSTALLED_VMLINUZ" ] && [ -f "$INSTALLED_VMLINUZ" ] && [ -d "/lib/modules" ]; then
    echo "[kernel-extract] Staging native container kernel for ${ARCH} from ${INSTALLED_VMLINUZ}..."
    rm -rf "$TEST_BOOT"
    mkdir -p "$TEST_BOOT/boot" "$TEST_BOOT/lib/modules"

    cp "$INSTALLED_VMLINUZ" "$TEST_BOOT/vmlinuz"
    cp -a /lib/modules/* "$TEST_BOOT/lib/modules/" 2>/dev/null || cp -a /usr/lib/modules/* "$TEST_BOOT/lib/modules/" 2>/dev/null || true

    if [ ! -d "$TEST_BOOT/usr/lib" ]; then
        mkdir -p "$TEST_BOOT/usr"
        ln -sf ../lib "$TEST_BOOT/usr/lib"
    fi

    KVER=$(ls "$TEST_BOOT/lib/modules" 2>/dev/null | head -n 1)
    if [ -n "$KVER" ]; then
        echo "[kernel-extract] Generating kernel module dependency database for $KVER..."
        depmod -b "${CURDIR}/${TEST_BOOT}" "$KVER"
    fi

    touch "${TEST_BOOT}/.kernel_extracted"
    echo "[kernel-extract] Successfully staged native container kernel for ${ARCH}."
    exit 0
fi

# 2. Cross-Architecture Build: Fetch official Debian kernel package for target architecture
echo "[kernel-extract] Cross-compiling for ${ARCH} (host: ${CURRENT_UNAME_M}). Fetching Debian ${DEB_ARCH} kernel..."
rm -rf "$TEST_BOOT" "$APT_DIR"
mkdir -p "$TEST_BOOT"
mkdir -p "$APT_DIR/etc/apt/trusted.gpg.d"
mkdir -p "$APT_DIR/var/lib/apt/lists/partial"
mkdir -p "$APT_DIR/var/cache/apt/archives/partial"
touch "$APT_DIR/var/lib/apt/status"

cp /usr/share/keyrings/debian-archive-keyring.gpg "$APT_DIR/etc/apt/trusted.gpg.d/debian.gpg" 2>/dev/null || true

echo "deb [arch=${DEB_ARCH}] http://deb.debian.org/debian/ trixie main" > "$APT_DIR/etc/apt/sources.list"

APT_OPTS="-o Dir=${CURDIR}/${APT_DIR} -o Dir::Etc::main=/dev/null -o Dir::Etc::parts=/dev/null"

echo "[kernel-extract] Updating sandboxed ${DEB_ARCH} APT index from deb.debian.org..."
apt-get ${APT_OPTS} update

echo "[kernel-extract] Resolving dependencies for ${KERNEL_PKG}..."
PKG=$(apt-cache ${APT_OPTS} show "${KERNEL_PKG}" | grep Depends | head -n 1 | awk '{print $2}' | tr -d ',')

echo "[kernel-extract] Downloading Debian ${DEB_ARCH} package: ${PKG}..."
cd "$TEST_BOOT"
apt-get ${APT_OPTS} download "${PKG}"

echo "[kernel-extract] Extracting kernel and module payloads..."
for f in *.deb; do
    [ -e "$f" ] || continue
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

cp boot/vmlinuz-* ./vmlinuz

if [ -d usr/lib ] && [ ! -d lib ]; then
    ln -s usr/lib lib
fi

KVER=$(ls lib/modules 2>/dev/null | head -n 1)
if [ -n "$KVER" ]; then
    echo "[kernel-extract] Generating kernel module dependency database for $KVER..."
    depmod -b "${CURDIR}/${TEST_BOOT}" "$KVER"
fi

touch "${CURDIR}/${TEST_BOOT}/.kernel_extracted"
echo "[kernel-extract] Successfully staged Debian ${DEB_ARCH} kernel for ${ARCH}."
