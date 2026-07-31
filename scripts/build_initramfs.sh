#!/bin/bash
# =========================================================================
# Initramfs Packager (Supports all architectures)
# =========================================================================
set -e

ARCH=$1
if [ -z "$ARCH" ]; then
    echo "Usage: $0 <arch>"
    exit 1
fi

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
TEST_BOOT="target/${ARCH}/test_boot"
BINARY="target/${RUST_TARGET}/release/rustyrouter"
DIRECT_DEPS="virtio_net virtio_pci virtio_mmio nft_masq nft_chain_nat nft_ct"

echo "[build] Creating initramfs staging area for ${ARCH}..."
rm -rf "$STAGING"
mkdir -p "$STAGING/proc" "$STAGING/sys" "$STAGING/dev" "$STAGING/run" "$STAGING/etc" "$STAGING/bin"
cp "$BINARY" "$STAGING/init"
chmod +x "$STAGING/init"
mknod -m 600 "$STAGING/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$STAGING/dev/null" c 1 3 2>/dev/null || true

KVER=$(ls "${TEST_BOOT}/lib/modules" 2>/dev/null | head -n 1)
if [ -n "$KVER" ]; then
    echo "[build] Generating kernel dependency database for ${KVER}..."
    depmod -b "${CURDIR}/${TEST_BOOT}" "$KVER"
    echo "[build] Staging ${ARCH} kernel modules..."
    mkdir -p "${STAGING}/lib/modules/${KVER}"
    
    for dep in ${DIRECT_DEPS}; do
        paths=$(modprobe -d "${CURDIR}/${TEST_BOOT}" -S "$KVER" --show-depends "$dep" 2>/dev/null | awk '/^insmod/ {print $2}')
        for path in ${paths}; do
            rel_path=${path#"${CURDIR}/${TEST_BOOT}/lib/modules/${KVER}/"}
            mkdir -p "${STAGING}/lib/modules/${KVER}/$(dirname "${rel_path}")"
            cp "$path" "${STAGING}/lib/modules/${KVER}/${rel_path}" 2>/dev/null || true
        done
    done
    
    if [ -d "${TEST_BOOT}/lib/modules/${KVER}/kernel/drivers/net/usb" ]; then
        echo "[build] Staging all USB network drivers and their dependencies..."
        find "${TEST_BOOT}/lib/modules/${KVER}/kernel/drivers/net/usb" -name "*.ko" -o -name "*.ko.*" | while read -r ko; do
            paths=$(modprobe -d "${CURDIR}/${TEST_BOOT}" -S "$KVER" --show-depends "$ko" 2>/dev/null | awk '/^insmod/ {print $2}')
            for path in ${paths}; do
                rel_path=${path#"${CURDIR}/${TEST_BOOT}/lib/modules/${KVER}/"}
                mkdir -p "${STAGING}/lib/modules/${KVER}/$(dirname "${rel_path}")"
                cp "$path" "${STAGING}/lib/modules/${KVER}/${rel_path}" 2>/dev/null || true
            done
        done
    fi
    
    echo "[build] Staging modules.dep and modules.alias for guest loading..."
    cp "${TEST_BOOT}/lib/modules/${KVER}/modules.dep" "${STAGING}/lib/modules/${KVER}/" 2>/dev/null || true
    cp "${TEST_BOOT}/lib/modules/${KVER}/modules.alias" "${STAGING}/lib/modules/${KVER}/" 2>/dev/null || true
fi

mkdir -p "${STAGING}/sbin"
ln -sf ../init "${STAGING}/sbin/modprobe"

echo "[build] Packaging initramfs into target/${ARCH}/initramfs.cpio.gz..."
(cd "$STAGING" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > ../initramfs.cpio.gz)
echo "[build] Initramfs archived successfully at: target/${ARCH}/initramfs.cpio.gz"
