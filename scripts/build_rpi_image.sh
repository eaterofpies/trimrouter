#!/bin/bash
# =========================================================================
# Raspberry Pi SD Card Image Builder (arm64 & armhf)
# =========================================================================
set -e

ARCH=$1
if [ -z "$ARCH" ]; then
    echo "Usage: $0 <arch>"
    exit 1
fi

case "$ARCH" in
    arm64)
        RUST_TARGET="aarch64-unknown-linux-musl"
        DEB_ARCH="arm64"
        KERNEL_FILE="kernel8.img"
        CONFIG_TXT="kernel=kernel8.img\narm_64bit=1\n\n[all]\ninitramfs pi_initramfs.cpio.gz followkernel\nenable_uart=1\ndtparam=audio=off\nhdmi_blanking=0"
        DTBS="bcm2710-rpi-zero-2-w.dtb bcm2710-rpi-3-b-plus.dtb"
        ;;
    armhf)
        RUST_TARGET="arm-unknown-linux-musleabihf"
        DEB_ARCH="armhf"
        KERNEL_FILE="kernel.img"
        CONFIG_TXT="kernel=kernel.img\narm_64bit=0\n\n[all]\ninitramfs pi_initramfs.cpio.gz followkernel\nenable_uart=1\ndtparam=audio=off\nhdmi_blanking=0"
        DTBS="bcm2708-rpi-zero-w.dtb"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

CURDIR=$(pwd)
RPI_INITRAMFS="target/${ARCH}/pi_initramfs.cpio.gz"
RPI_STAGING="target/${ARCH}/pi_initramfs"
RPI_BOOT_DIR="target/${ARCH}/pi_boot"
RPI_DEB_DIR="target/${ARCH}/rpi_deb"
RPI_IMAGE="target/${ARCH}/rustyrouter.img"
BINARY="target/${RUST_TARGET}/release/rustyrouter"
APT_DIR="target/${ARCH}/apt"

# 1. APT download & extract stamp
if [ ! -f "${RPI_DEB_DIR}/.extracted_stamp" ]; then
    echo "[apt-rpi] Setting up sandboxed repository for ${ARCH}..."
    rm -rf "${RPI_DEB_DIR}" "${APT_DIR}"
    mkdir -p "${RPI_DEB_DIR}"
    mkdir -p "${APT_DIR}/etc/apt/trusted.gpg.d"
    mkdir -p "${APT_DIR}/var/lib/apt/lists/partial"
    mkdir -p "${APT_DIR}/var/cache/apt/archives/partial"
    touch "${APT_DIR}/var/lib/apt/status"
    cp /usr/share/keyrings/debian-archive-keyring.gpg "${APT_DIR}/etc/apt/trusted.gpg.d/debian.gpg"

    echo "deb [arch=${DEB_ARCH} trusted=yes] https://archive.raspberrypi.org/debian/ bookworm main" > "${APT_DIR}/etc/apt/sources.list"

    APT_OPTS="-o Dir=${CURDIR}/${APT_DIR} -o Dir::Etc::main=/dev/null -o Dir::Etc::parts=/dev/null"

    echo "Updating sandboxed ${ARCH} APT package index..."
    apt-get ${APT_OPTS} update
    echo "Downloading latest ${ARCH} kernel & bootloader..."
    cd "${RPI_DEB_DIR}"
    apt-get ${APT_OPTS} download raspberrypi-kernel raspberrypi-bootloader

    echo "Extracting packages for ${ARCH}..."
    for f in raspberrypi-kernel_*.deb raspberrypi-bootloader_*.deb; do
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
    touch .extracted_stamp
    cd "${CURDIR}"
fi

# 2. Package RPi initramfs
echo "[build-rpi] Creating Pi initramfs staging area for ${ARCH}..."
rm -rf "$RPI_STAGING"
mkdir -p "$RPI_STAGING/proc" "$RPI_STAGING/sys" "$RPI_STAGING/dev" "$RPI_STAGING/run" "$RPI_STAGING/etc" "$RPI_STAGING/bin"
cp "$BINARY" "$RPI_STAGING/init"
chmod +x "$RPI_STAGING/init"
mknod -m 600 "$RPI_STAGING/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$RPI_STAGING/dev/null" c 1 3 2>/dev/null || true

echo "[build-rpi] Staging netfilter modules for ${ARCH}..."
mkdir -p "$RPI_STAGING/lib/modules"
find "${RPI_DEB_DIR}/lib/modules" -mindepth 1 -maxdepth 1 -type d | while read -r mod_dir; do
    rel_name=$(basename "$mod_dir")
    mkdir -p "$RPI_STAGING/lib/modules/${rel_name}/kernel/net/netfilter"
    if [ -d "$mod_dir/kernel/net/netfilter" ]; then
        cp -r "$mod_dir/kernel/net/netfilter"/* "$RPI_STAGING/lib/modules/${rel_name}/kernel/net/netfilter/" 2>/dev/null || true
    fi
    if [ -d "$mod_dir/kernel/net/ipv4" ]; then
        mkdir -p "$RPI_STAGING/lib/modules/${rel_name}/kernel/net/ipv4"
        cp -r "$mod_dir/kernel/net/ipv4"/* "$RPI_STAGING/lib/modules/${rel_name}/kernel/net/ipv4/" 2>/dev/null || true
    fi
    if [ -d "$mod_dir/kernel/net/ipv6" ]; then
        mkdir -p "$RPI_STAGING/lib/modules/${rel_name}/kernel/net/ipv6"
        cp -r "$mod_dir/kernel/net/ipv6"/* "$RPI_STAGING/lib/modules/${rel_name}/kernel/net/ipv6/" 2>/dev/null || true
    fi

    # Stage USB network drivers and their dependencies
    if [ -d "${RPI_DEB_DIR}/lib/modules/${rel_name}/kernel/drivers/net/usb" ]; then
        echo "[build-rpi] Staging USB network drivers and dependencies for ${rel_name}..."
        find "${RPI_DEB_DIR}/lib/modules/${rel_name}/kernel/drivers/net/usb" -name "*.ko" -o -name "*.ko.*" | while read -r ko; do
            mod_name=$(basename "$ko" | cut -d. -f1)
            paths=$(modprobe -d "${CURDIR}/${RPI_DEB_DIR}" -S "${rel_name}" --show-depends "$mod_name" 2>/dev/null | awk '/^insmod/ {print $2}')
            for path in ${paths}; do
                rel_path=${path#"${CURDIR}/${RPI_DEB_DIR}/lib/modules/${rel_name}/"}
                mkdir -p "$RPI_STAGING/lib/modules/${rel_name}/$(dirname "${rel_path}")"
                cp "$path" "$RPI_STAGING/lib/modules/${rel_name}/${rel_path}" 2>/dev/null || true
            done
        done
    fi
    
    # Stage modules.dep and modules.alias
    cp "${RPI_DEB_DIR}/lib/modules/${rel_name}/modules.dep" "$RPI_STAGING/lib/modules/${rel_name}/" 2>/dev/null || true
    cp "${RPI_DEB_DIR}/lib/modules/${rel_name}/modules.alias" "$RPI_STAGING/lib/modules/${rel_name}/" 2>/dev/null || true

    # Decompress staged modules on host
    echo "[build-rpi] Decompressing staged kernel modules on host for ${rel_name}..."
    find "$RPI_STAGING/lib/modules/${rel_name}" -type f \( -name "*.ko.xz" -o -name "*.ko.gz" -o -name "*.ko.zst" \) | while read -r comp_ko; do
        if [[ "$comp_ko" == *.xz ]]; then
            xz -d "$comp_ko" 2>/dev/null || true
        elif [[ "$comp_ko" == *.gz ]]; then
            gzip -d "$comp_ko" 2>/dev/null || true
        elif [[ "$comp_ko" == *.zst ]]; then
            zstd -d --rm "$comp_ko" 2>/dev/null || true
        fi
    done

    # Strip decompression extensions from modules.dep
    if [ -f "$RPI_STAGING/lib/modules/${rel_name}/modules.dep" ]; then
        sed -i 's/\.ko\.xz/.ko/g; s/\.ko\.gz/.ko/g; s/\.ko\.zst/.ko/g' "$RPI_STAGING/lib/modules/${rel_name}/modules.dep"
    fi
done

echo "[build-rpi] Packaging Pi initramfs into ${RPI_INITRAMFS}..."
mkdir -p "target/${ARCH}"
(cd "$RPI_STAGING" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > ../pi_initramfs.cpio.gz)

# 3. Build image
echo "[build-rpi] Staging boot partition directory for ${ARCH}..."
rm -rf "$RPI_BOOT_DIR"
mkdir -p "$RPI_BOOT_DIR"
cp "$RPI_INITRAMFS" "$RPI_BOOT_DIR/"
cp "${RPI_DEB_DIR}/boot/bootcode.bin" "$RPI_BOOT_DIR/"
cp "${RPI_DEB_DIR}/boot/fixup.dat" "$RPI_BOOT_DIR/"
cp "${RPI_DEB_DIR}/boot/start.elf" "$RPI_BOOT_DIR/"
cp "${RPI_DEB_DIR}/boot/${KERNEL_FILE}" "$RPI_BOOT_DIR/"
for dtb in ${DTBS}; do
    cp "${RPI_DEB_DIR}/boot/${dtb}" "$RPI_BOOT_DIR/"
done
cp -r "${RPI_DEB_DIR}/boot/overlays" "$RPI_BOOT_DIR/"

echo "Staging configuration boot scripts for ${ARCH}..."
echo -e "${CONFIG_TXT}" > "$RPI_BOOT_DIR/config.txt"
echo "console=serial0,115200 console=tty1 root=/dev/ram0 rdinit=/init quiet panic=-1 net.ifnames=0 rustyrouter.lan_ip=192.168.1.1/24 rustyrouter.wan_mac=00:11:22:33:44:55 rustyrouter.lan_mac=66:77:88:99:aa:bb" > "$RPI_BOOT_DIR/cmdline.txt"

echo "[build-rpi] Allocating blank raw disk block file for ${ARCH}..."
dd if=/dev/zero of="$RPI_IMAGE" bs=1M count=128 2>/dev/null
parted -s "$RPI_IMAGE" mklabel msdos mkpart primary fat32 1MiB 100%

echo "[build-rpi] Formatting FAT32 partition in raw disk image..."
mformat -i "${RPI_IMAGE}@@1M" -F

echo "[build-rpi] Writing boot sector payload files..."
mcopy -i "${RPI_IMAGE}@@1M" "$RPI_BOOT_DIR/bootcode.bin" ::/
mcopy -i "${RPI_IMAGE}@@1M" "$RPI_BOOT_DIR/start.elf" ::/
mcopy -i "${RPI_IMAGE}@@1M" "$RPI_BOOT_DIR/fixup.dat" ::/
mcopy -i "${RPI_IMAGE}@@1M" "$RPI_BOOT_DIR/${KERNEL_FILE}" ::/
mcopy -i "${RPI_IMAGE}@@1M" "$RPI_BOOT_DIR/pi_initramfs.cpio.gz" ::/
mcopy -i "${RPI_IMAGE}@@1M" "$RPI_BOOT_DIR/config.txt" ::/
mcopy -i "${RPI_IMAGE}@@1M" "$RPI_BOOT_DIR/cmdline.txt" ::/
mcopy -i "${RPI_IMAGE}@@1M" "$RPI_BOOT_DIR"/*.dtb ::/
mcopy -s -i "${RPI_IMAGE}@@1M" "$RPI_BOOT_DIR/overlays" ::/

echo "========================================================="
echo "SUCCESSFULLY CREATED ${ARCH} IMAGE: ${RPI_IMAGE}"
echo "========================================================="
