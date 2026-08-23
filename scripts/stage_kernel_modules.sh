#!/bin/bash
# =========================================================================
# Kernel Module Pre-Stager (Caches kernel module dependency resolution)
# =========================================================================
set -e

ARCH=$1
if [ -z "$ARCH" ]; then
    echo "Usage: $0 <arch>"
    exit 1
fi

CURDIR=$(pwd)
TEST_BOOT="target/${ARCH}/test_boot"
STAGED_MODULES="target/${ARCH}/staged_modules"
STAMP_FILE="target/${ARCH}/.modules_staged"
DIRECT_DEPS="virtio_net virtio_pci virtio_mmio virtio_blk virtio_scsi usb_storage uas xhci_pci xhci_pci_renesas xhci_hcd ehci_pci ehci_hcd uhci_hcd ohci_pci ohci_hcd sd_mod scsi_mod mmc_block sdhci sdhci_pci sdhci_acpi rtsx_pci_sdmmc rtsx_usb_sdmmc ahci libahci ata_piix ata_generic sata_nv sata_via sata_sis sata_sil sata_sil24 pata_acpi pata_amd nvme nvme_core erofs nft_masq nft_chain_nat nft_ct fat vfat nls_cp437 nls_ascii nls_utf8 nls_iso8859_1"

if [ ! -d "${TEST_BOOT}/lib/modules" ]; then
    echo "[build] ERROR: Kernel modules directory '${TEST_BOOT}/lib/modules' not found. Run './scripts/extract_kernel.sh $ARCH' or 'make'."
    exit 1
fi

echo "[build] Staging kernel modules for ${ARCH}..."
rm -rf "$STAGED_MODULES"
mkdir -p "$STAGED_MODULES"

KVER=$(ls "${TEST_BOOT}/lib/modules" 2>/dev/null | head -n 1)
if [ -n "$KVER" ]; then
    echo "[build] Generating kernel dependency database for ${KVER}..."
    depmod -b "${CURDIR}/${TEST_BOOT}" "$KVER"
    mkdir -p "${STAGED_MODULES}/lib/modules/${KVER}"

    for dep in ${DIRECT_DEPS}; do
        paths=$(modprobe -d "${CURDIR}/${TEST_BOOT}" -S "$KVER" --show-depends "$dep" 2>/dev/null | awk '/^insmod/ {print $2}')
        for path in ${paths}; do
            rel_path=${path#"${CURDIR}/${TEST_BOOT}/lib/modules/${KVER}/"}
            mkdir -p "${STAGED_MODULES}/lib/modules/${KVER}/$(dirname "${rel_path}")"
            cp "$path" "${STAGED_MODULES}/lib/modules/${KVER}/${rel_path}" 2>/dev/null || true
        done
    done

    if [ -d "${TEST_BOOT}/lib/modules/${KVER}/kernel/drivers/net/usb" ]; then
        echo "[build] Staging all USB network drivers and their dependencies..."
        find "${TEST_BOOT}/lib/modules/${KVER}/kernel/drivers/net/usb" -name "*.ko" -o -name "*.ko.*" | while read -r ko; do
            mod_name=$(basename "$ko" | cut -d. -f1)
            paths=$(modprobe -d "${CURDIR}/${TEST_BOOT}" -S "$KVER" --show-depends "$mod_name" 2>/dev/null | awk '/^insmod/ {print $2}')
            for path in ${paths}; do
                rel_path=${path#"${CURDIR}/${TEST_BOOT}/lib/modules/${KVER}/"}
                mkdir -p "${STAGED_MODULES}/lib/modules/${KVER}/$(dirname "${rel_path}")"
                cp "$path" "${STAGED_MODULES}/lib/modules/${KVER}/${rel_path}" 2>/dev/null || true
            done
        done
    fi

    echo "[build] Staging modules.dep and modules.alias for guest loading..."
    cp "${TEST_BOOT}/lib/modules/${KVER}/modules.dep" "${STAGED_MODULES}/lib/modules/${KVER}/" 2>/dev/null || true
    cp "${TEST_BOOT}/lib/modules/${KVER}/modules.alias" "${STAGED_MODULES}/lib/modules/${KVER}/" 2>/dev/null || true

    # Decompress staged modules on host
    echo "[build] Decompressing staged kernel modules on host for ${KVER}..."
    find "$STAGED_MODULES/lib/modules/${KVER}" -type f \( -name "*.ko.xz" -o -name "*.ko.gz" -o -name "*.ko.zst" \) | while read -r comp_ko; do
        if [[ "$comp_ko" == *.xz ]]; then
            xz -d "$comp_ko" 2>/dev/null || true
        elif [[ "$comp_ko" == *.gz ]]; then
            gzip -d "$comp_ko" 2>/dev/null || true
        elif [[ "$comp_ko" == *.zst ]]; then
            zstd -d --rm "$comp_ko" 2>/dev/null || true
        fi
    done

    # Strip decompression extensions from modules.dep
    if [ -f "$STAGED_MODULES/lib/modules/${KVER}/modules.dep" ]; then
        sed -i 's/\.ko\.xz/.ko/g; s/\.ko\.gz/.ko/g; s/\.ko\.zst/.ko/g' "$STAGED_MODULES/lib/modules/${KVER}/modules.dep"
    fi
fi

touch "$STAMP_FILE"
echo "[build] Staged kernel modules cached at: ${STAGED_MODULES}"
