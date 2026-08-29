#!/bin/bash
# =========================================================================
# trimrouter SD Card / Disk Image Builder (x86_64, arm64, armhf)
# =========================================================================
set -e

ARCH=$1
if [ -z "$ARCH" ]; then
    echo "Usage: $0 <arch> [config_file] [image_name]"
    exit 1
fi
CONFIG_FILE=${2:-config/trimrouter.toml}
IMAGE_NAME=${3:-trimrouter.img}

CURDIR=$(pwd)
IMAGE="target/${ARCH}/${IMAGE_NAME}"
mkdir -p "target/${ARCH}"

# Validate configuration file
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[build-image] ERROR: Configuration file '$CONFIG_FILE' not found."
    exit 1
fi

case "$ARCH" in
    x86_64)
        RUST_TARGET="x86_64-unknown-linux-musl"
        BINARY="target/${RUST_TARGET}/release/trimrouter"
        KERNEL="target/x86_64/test_boot/vmlinuz"
        if [ "$IMAGE_NAME" = "trimrouter-test.img" ]; then
            INITRAMFS="target/x86_64/initramfs-test.cpio.gz"
            DEFAULT_CMDLINE="console=tty0 console=ttyS0,115200 loglevel=7 panic=1 net.ifnames=0"
        else
            INITRAMFS="target/x86_64/initramfs.cpio.gz"
            DEFAULT_CMDLINE="console=ttyS0,115200 console=tty0 loglevel=7 panic=1 net.ifnames=0"
        fi
        CMDLINE="${TRIMROUTER_CMDLINE:-$DEFAULT_CMDLINE}"

        # Validate prerequisite build artifacts
        if [ ! -f "$KERNEL" ]; then
            echo "[build-image] ERROR: Kernel '$KERNEL' not found. Run './scripts/extract_kernel.sh x86_64' or 'make'."
            exit 1
        fi
        if [ ! -f "$INITRAMFS" ]; then
            echo "[build-image] ERROR: Initramfs '$INITRAMFS' not found. Run './scripts/build_initramfs.sh x86_64' or 'make'."
            exit 1
        fi
        if [ ! -f "target/x86_64/modules.erofs" ]; then
            echo "[build-image] ERROR: EROFS module image 'target/x86_64/modules.erofs' not found. Run 'make target/x86_64/modules.erofs'."
            exit 1
        fi

        # Check required host utilities
        for tool in dd parted mformat mcopy objcopy; do
            if ! command -v "$tool" >/dev/null 2>&1; then
                echo "[build-image] ERROR: Required tool '$tool' is not installed."
                exit 1
            fi
        done

        STUB="/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
        if [ ! -f "$STUB" ]; then
            echo "[build-image] ERROR: systemd-boot EFI stub not found at $STUB"
            echo "[build-image] Install it with: sudo apt-get install -y systemd-boot-efi"
            exit 1
        fi

        echo "[build-image] Building disk image for x86_64 (UEFI)..."

        # 1. Allocate blank raw disk image with bootable FAT32 partition (MBR table)
        dd if=/dev/zero of="$IMAGE" bs=1M count=256 2>/dev/null
        parted -s "$IMAGE" mklabel msdos mkpart primary fat32 1MiB 240MiB set 1 boot on

        # 2. Format partition as FAT32 with label TRIMROUTER
        mformat -v TRIMROUTER -i "${IMAGE}@@1M" -F

        # 3. Build Unified Kernel Image (UKI) for UEFI firmware
        UKI_OUT="target/x86_64/BOOTX64.EFI"
        CMDLINE_FILE="target/x86_64/cmdline.txt"
        printf "%s" "$CMDLINE" > "$CMDLINE_FILE"

        objcopy \
            --add-section .cmdline="$CMDLINE_FILE" --change-section-vma .cmdline=0x14dfb0000 \
            --add-section .linux="$KERNEL" --change-section-vma .linux=0x14dfc0000 \
            --add-section .initrd="$INITRAMFS" --change-section-vma .initrd=0x14ebd0000 \
            "$STUB" "$UKI_OUT"

        # 4. Write EFI boot payloads to the FAT32 partition
        mmd -i "${IMAGE}@@1M" ::/EFI 2>/dev/null || true
        mmd -i "${IMAGE}@@1M" ::/EFI/BOOT 2>/dev/null || true
        mcopy -i "${IMAGE}@@1M" "$UKI_OUT" ::/EFI/BOOT/BOOTX64.EFI

        # 5. Write command-line and configuration files
        mcopy -i "${IMAGE}@@1M" "$CMDLINE_FILE" ::/cmdline.txt
        mmd -i "${IMAGE}@@1M" ::/config 2>/dev/null || true
        mcopy -i "${IMAGE}@@1M" "${CONFIG_FILE}" ::/config/trimrouter.toml

        # 6. Bundle full module tree into EROFS image
        mcopy -i "${IMAGE}@@1M" "target/x86_64/modules.erofs" ::/modules.erofs
        ;;

    arm64|armhf)
        FIRMWARE_DIR="/usr/lib/raspi-firmware"
        if [ ! -d "$FIRMWARE_DIR" ]; then
            echo "[build-rpi] ERROR: Debian Raspberry Pi firmware directory '$FIRMWARE_DIR' not found."
            echo "[build-rpi] Please install it using: apt-get install -y raspi-firmware"
            exit 1
        fi

        KERNEL="target/${ARCH}/test_boot/vmlinuz"
        if [ "$IMAGE_NAME" = "trimrouter-test.img" ]; then
            INITRAMFS="target/${ARCH}/initramfs-test.cpio.gz"
        else
            INITRAMFS="target/${ARCH}/initramfs.cpio.gz"
        fi

        if [ ! -f "$KERNEL" ]; then
            echo "[build-rpi] ERROR: Kernel '$KERNEL' not found. Run './scripts/extract_kernel.sh ${ARCH}' or 'make'."
            exit 1
        fi
        if [ ! -f "$INITRAMFS" ]; then
            echo "[build-rpi] ERROR: Initramfs '$INITRAMFS' not found. Run './scripts/build_initramfs.sh ${ARCH}' or 'make'."
            exit 1
        fi

        case "$ARCH" in
            arm64)
                CONFIG_TXT="kernel=vmlinuz\narm_64bit=1\n\n[all]\ninitramfs initramfs.cpio.gz followkernel\nenable_uart=1\ndtparam=audio=off\nhdmi_blanking=0"
                ;;
            armhf)
                CONFIG_TXT="kernel=vmlinuz\narm_64bit=0\n\n[all]\ninitramfs initramfs.cpio.gz followkernel\nenable_uart=1\ndtparam=audio=off\nhdmi_blanking=0"
                ;;
        esac

        RPI_BOOT_DIR="target/${ARCH}/pi_boot"
        echo "[build-rpi] Staging boot partition directory for ${ARCH} from installed Debian raspi-firmware..."
        rm -rf "$RPI_BOOT_DIR"
        mkdir -p "$RPI_BOOT_DIR"

        # Copy kernel and initramfs
        cp "$KERNEL" "$RPI_BOOT_DIR/vmlinuz"
        cp "$INITRAMFS" "$RPI_BOOT_DIR/initramfs.cpio.gz"

        # Copy Debian raspi-firmware bootloader files
        cp "$FIRMWARE_DIR"/bootcode.bin "$RPI_BOOT_DIR/" 2>/dev/null || true
        cp "$FIRMWARE_DIR"/fixup*.dat "$RPI_BOOT_DIR/" 2>/dev/null || true
        cp "$FIRMWARE_DIR"/start*.elf "$RPI_BOOT_DIR/" 2>/dev/null || true

        # Copy DTBs and overlays
        for dtb in "$FIRMWARE_DIR"/*.dtb; do
            [ -e "$dtb" ] && cp "$dtb" "$RPI_BOOT_DIR/"
        done
        if [ -d "$FIRMWARE_DIR/overlays" ]; then
            cp -r "$FIRMWARE_DIR/overlays" "$RPI_BOOT_DIR/"
        fi

        echo "[build-rpi] Staging configuration boot scripts for ${ARCH}..."
        echo -e "${CONFIG_TXT}" > "$RPI_BOOT_DIR/config.txt"
        echo "console=serial0,115200 console=tty1 root=/dev/ram0 rdinit=/init quiet panic=-1 net.ifnames=0" > "$RPI_BOOT_DIR/cmdline.txt"

        echo "[build-rpi] Allocating blank raw disk block file for ${ARCH}..."
        dd if=/dev/zero of="$IMAGE" bs=1M count=256 2>/dev/null
        parted -s "$IMAGE" mklabel msdos mkpart primary fat32 1MiB 240MiB

        echo "[build-rpi] Formatting FAT32 partition in raw disk image..."
        mformat -v TRIMROUTER -i "${IMAGE}@@1M" -F

        echo "[build-rpi] Writing boot sector payload files..."
        for f in "$RPI_BOOT_DIR"/*; do
            if [ -f "$f" ]; then
                mcopy -i "${IMAGE}@@1M" "$f" ::/
            fi
        done
        if [ -d "$RPI_BOOT_DIR/overlays" ]; then
            mcopy -s -i "${IMAGE}@@1M" "$RPI_BOOT_DIR/overlays" ::/
        fi

        mmd -i "${IMAGE}@@1M" ::/config 2>/dev/null || true
        mcopy -i "${IMAGE}@@1M" "${CONFIG_FILE}" ::/config/trimrouter.toml

        if [ -f "target/${ARCH}/modules.erofs" ]; then
            mcopy -i "${IMAGE}@@1M" "target/${ARCH}/modules.erofs" ::/modules.erofs
        fi
        ;;
esac

echo "========================================================="
echo "SUCCESSFULLY CREATED ${ARCH} IMAGE: ${IMAGE}"
echo "========================================================="
