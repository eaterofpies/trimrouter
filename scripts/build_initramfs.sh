#!/bin/bash
# =========================================================================
# Initramfs Packager (Supports prod/test modes and all architectures)
# =========================================================================
set -e

ARCH=$1
MODE=$2 # "prod" or "test"
if [ -z "$ARCH" ]; then
    echo "Usage: $0 <arch> [prod|test]"
    exit 1
fi
MODE=${MODE:-prod}

case "$ARCH" in
    x86_64)
        RUST_TARGET="x86_64-unknown-linux-musl"
        ;;
    arm64)
        RUST_TARGET="aarch64-unknown-linux-musl"
        ;;
    armhf)
        RUST_TARGET="arm-unknown-linux-musleabihf"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

CURDIR=$(pwd)
STAGING="target/${ARCH}/staging"
STAGED_MODULES="target/${ARCH}/staged_modules"

if [ "$MODE" = "test" ]; then
    BINARY="target/${RUST_TARGET}/test-fast/trimrouter"
    TEST_BINARY="target/${RUST_TARGET}/test-fast/integration_test"
else
    BINARY="target/${RUST_TARGET}/release/trimrouter"
    TEST_BINARY="target/${RUST_TARGET}/release/integration_test"
fi

# Validate required input binaries and staged modules
if [ ! -f "$BINARY" ]; then
    echo "[build] ERROR: Target binary '$BINARY' not found."
    exit 1
fi

if [ "$MODE" = "test" ] && [ ! -f "$TEST_BINARY" ]; then
    echo "[build] ERROR: Test binary '$TEST_BINARY' not found."
    exit 1
fi

if [ ! -d "$STAGED_MODULES" ]; then
    echo "[build] ERROR: Staged kernel modules directory '$STAGED_MODULES' not found. Run './scripts/stage_kernel_modules.sh $ARCH' or 'make'."
    exit 1
fi

echo "[build] Assembling initramfs staging area for ${ARCH} (mode: ${MODE})..."
rm -rf "$STAGING"
mkdir -p "$STAGING/proc" "$STAGING/sys" "$STAGING/dev" "$STAGING/run" "$STAGING/etc" "$STAGING/bin" "$STAGING/sbin"

# Copy pre-staged kernel modules
cp -a "$STAGED_MODULES"/* "$STAGING/" 2>/dev/null || true

if [ "$MODE" = "test" ]; then
    echo "[build] Copying test runner as /init..."
    cp "$TEST_BINARY" "$STAGING/init"
    cp "$BINARY" "$STAGING/bin/trimrouter"
    chmod +x "$STAGING/init" "$STAGING/bin/trimrouter"
else
    echo "[build] Copying production trimrouter as /init..."
    cp "$BINARY" "$STAGING/init"
    cp "$BINARY" "$STAGING/bin/trimrouter"
    chmod +x "$STAGING/init" "$STAGING/bin/trimrouter"
fi

mknod -m 600 "$STAGING/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$STAGING/dev/null" c 1 3 2>/dev/null || true
ln -sf ../init "${STAGING}/sbin/modprobe"

if [ "$MODE" = "test" ]; then
    INITRAMFS_NAME="initramfs-test.cpio.gz"
else
    INITRAMFS_NAME="initramfs.cpio.gz"
fi

echo "[build] Packaging initramfs into target/${ARCH}/${INITRAMFS_NAME}..."
(cd "$STAGING" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > ../${INITRAMFS_NAME})
echo "[build] Initramfs archived successfully at: target/${ARCH}/${INITRAMFS_NAME}"
