#!/bin/bash
# =========================================================================
# Generic Kernel Stager (Uses pinned local host/container kernel only)
# =========================================================================
set -e

ARCH=$1
if [ -z "$ARCH" ]; then
    echo "Usage: $0 <arch>"
    exit 1
fi

case "$ARCH" in
    x86_64)
        HOST_ARCH="x86_64"
        KERNEL_PKG="linux-image-amd64"
        ;;
    arm64)
        HOST_ARCH="aarch64"
        KERNEL_PKG="linux-image-arm64"
        ;;
    armhf)
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
CURRENT_UNAME_M=$(uname -m)

# 1. Validate matching architecture
if [ "$CURRENT_UNAME_M" != "$HOST_ARCH" ]; then
    echo "[kernel-extract] ERROR: Architecture mismatch: Host is '$CURRENT_UNAME_M' but target is '$ARCH' (expected '$HOST_ARCH')."
    echo "[kernel-extract] Build inside a Docker container matching the target architecture."
    exit 1
fi

# 2. Locate installed kernel image
INSTALLED_VMLINUZ=$(ls -1 /boot/vmlinuz-* 2>/dev/null | head -n 1 || true)
if [ -z "$INSTALLED_VMLINUZ" ] || [ ! -f "$INSTALLED_VMLINUZ" ]; then
    echo "[kernel-extract] ERROR: No installed kernel found in /boot/vmlinuz-*."
    echo "[kernel-extract] Please install the pinned kernel package '${KERNEL_PKG}' (e.g. via Dockerfile apt-get install)."
    exit 1
fi

# 3. Locate installed kernel modules directory
MODULES_SRC=""
if [ -d "/usr/lib/modules" ] && [ "$(ls -A /usr/lib/modules 2>/dev/null)" ]; then
    MODULES_SRC="/usr/lib/modules"
elif [ -d "/lib/modules" ] && [ "$(ls -A /lib/modules 2>/dev/null)" ]; then
    MODULES_SRC="/lib/modules"
else
    echo "[kernel-extract] ERROR: No kernel modules directory found in /lib/modules or /usr/lib/modules."
    echo "[kernel-extract] Please install the pinned kernel package '${KERNEL_PKG}'."
    exit 1
fi

echo "[kernel-extract] Staging pinned container kernel for ${ARCH} from ${INSTALLED_VMLINUZ}..."
rm -rf "$TEST_BOOT"
mkdir -p "$TEST_BOOT/boot" "$TEST_BOOT/lib/modules"

# Copy kernel image and module hierarchy
cp "$INSTALLED_VMLINUZ" "$TEST_BOOT/vmlinuz"
cp -a "$MODULES_SRC"/* "$TEST_BOOT/lib/modules/"

# Support usr-merged layout symlinks
if [ ! -d "$TEST_BOOT/usr/lib" ]; then
    mkdir -p "$TEST_BOOT/usr"
    ln -sf ../lib "$TEST_BOOT/usr/lib"
fi

# Generate depmod database for guest boot
KVER=$(ls "$TEST_BOOT/lib/modules" 2>/dev/null | head -n 1)
if [ -z "$KVER" ]; then
    echo "[kernel-extract] ERROR: No kernel version subdirectory found in $MODULES_SRC."
    exit 1
fi

echo "[kernel-extract] Generating kernel module dependency database for $KVER..."
depmod -b "${CURDIR}/${TEST_BOOT}" "$KVER"

touch "${TEST_BOOT}/.kernel_extracted"
echo "[kernel-extract] Successfully staged pinned container kernel for ${ARCH}."
