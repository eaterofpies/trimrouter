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
TEST_BOOT="target/${ARCH}/test_boot"
BINARY="target/${RUST_TARGET}/release/trimrouter"
TEST_BINARY="target/${RUST_TARGET}/release/integration_test"
DIRECT_DEPS="virtio_net virtio_pci virtio_mmio virtio_blk usb_storage uas sd_mod mmc_block sdhci sdhci_pci ahci nft_masq nft_chain_nat nft_ct fat vfat nls_cp437 nls_ascii nls_utf8"

echo "[build] Creating initramfs staging area for ${ARCH} (mode: ${MODE})..."
rm -rf "$STAGING"
mkdir -p "$STAGING/proc" "$STAGING/sys" "$STAGING/dev" "$STAGING/run" "$STAGING/etc" "$STAGING/bin"

if [ "$MODE" = "test" ]; then
    echo "[build] Copying test runner as /init..."
    cp "$TEST_BINARY" "$STAGING/init"
    cp "$BINARY" "$STAGING/bin/trimrouter"
    chmod +x "$STAGING/init" "$STAGING/bin/trimrouter"
else
    echo "[build] Copying production trimrouter as /init..."
    cp "$BINARY" "$STAGING/init"
    chmod +x "$STAGING/init"
fi

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
            mod_name=$(basename "$ko" | cut -d. -f1)
            paths=$(modprobe -d "${CURDIR}/${TEST_BOOT}" -S "$KVER" --show-depends "$mod_name" 2>/dev/null | awk '/^insmod/ {print $2}')
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

    # Decompress staged modules on host
    echo "[build] Decompressing staged kernel modules on host for ${KVER}..."
    find "$STAGING/lib/modules/${KVER}" -type f \( -name "*.ko.xz" -o -name "*.ko.gz" -o -name "*.ko.zst" \) | while read -r comp_ko; do
        if [[ "$comp_ko" == *.xz ]]; then
            xz -d "$comp_ko" 2>/dev/null || true
        elif [[ "$comp_ko" == *.gz ]]; then
            gzip -d "$comp_ko" 2>/dev/null || true
        elif [[ "$comp_ko" == *.zst ]]; then
            zstd -d --rm "$comp_ko" 2>/dev/null || true
        fi
    done

    # Strip decompression extensions from modules.dep
    if [ -f "$STAGING/lib/modules/${KVER}/modules.dep" ]; then
        sed -i 's/\.ko\.xz/.ko/g; s/\.ko\.gz/.ko/g; s/\.ko\.zst/.ko/g' "$STAGING/lib/modules/${KVER}/modules.dep"
    fi
fi

mkdir -p "${STAGING}/sbin"
ln -sf ../init "${STAGING}/sbin/modprobe"

if [ "$MODE" = "test" ]; then
    INITRAMFS_NAME="initramfs-test.cpio.gz"
else
    INITRAMFS_NAME="initramfs.cpio.gz"
fi

echo "[build] Packaging initramfs into target/${ARCH}/${INITRAMFS_NAME}..."
(cd "$STAGING" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > ../${INITRAMFS_NAME})
echo "[build] Initramfs archived successfully at: target/${ARCH}/${INITRAMFS_NAME}"
