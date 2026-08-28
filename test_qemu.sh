#!/bin/bash
set -e

# =========================================================================
# QEMU Interactive Test Runner (Supports all architectures)
# =========================================================================
# Detect target architecture (defaults to x86_64)
ARCH=${ARCH:-x86_64}

# Ensure the VM image is compiled
make target/${ARCH}/trimrouter.img ARCH=${ARCH}

KERNEL="target/${ARCH}/test_boot/vmlinuz"
INITRAMFS="target/${ARCH}/initramfs.cpio.gz"
IMAGE="target/${ARCH}/trimrouter.img"

if [ ! -f "$KERNEL" ]; then
    echo "[qemu] ERROR: Kernel image not found at $KERNEL."
    exit 1
fi

echo "[qemu] Booting interactive router VM for ${ARCH}..."
echo "Press Ctrl+A then X to exit QEMU"
echo "===================================================="

if [ "$ARCH" = "x86_64" ]; then
    OVMF=""
    for candidate in /usr/share/OVMF/OVMF.fd /usr/share/ovmf/OVMF.fd /usr/share/qemu/OVMF.fd /usr/share/OVMF/OVMF_CODE_4M.fd; do
        if [ -f "$candidate" ]; then
            OVMF="$candidate"
            break
        fi
    done
    if [ -z "$OVMF" ]; then
        echo "[qemu] ERROR: OVMF UEFI firmware not found. Install ovmf: sudo apt-get install -y ovmf"
        exit 1
    fi
    exec qemu-system-x86_64 \
      -m 256 \
      -bios "$OVMF" \
      -drive file="$IMAGE",format=raw,media=disk,if=virtio \
      -netdev user,id=wan0,net=10.0.2.0/24 \
      -device virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56 \
      -netdev user,id=lan0,net=192.168.1.0/24 \
      -device virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57 \
      -nographic
elif [ "$ARCH" = "arm64" ]; then
    exec qemu-system-aarch64 \
      -M virt \
      -cpu cortex-a53 \
      -m 1024 \
      -kernel "$KERNEL" \
      -initrd "$INITRAMFS" \
      -drive file="$IMAGE",format=raw,media=disk,if=virtio \
      -device virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56 \
      -netdev user,id=wan0 \
      -device virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57 \
      -netdev user,id=lan0 \
      -append "console=ttyAMA0,115200 root=/dev/ram0 rdinit=/init quiet net.ifnames=0" \
      -nographic
elif [ "$ARCH" = "armhf" ]; then
    exec qemu-system-arm \
      -M virt \
      -cpu cortex-a7 \
      -m 1024 \
      -kernel "$KERNEL" \
      -initrd "$INITRAMFS" \
      -drive file="$IMAGE",format=raw,media=disk,if=virtio \
      -device virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56 \
      -netdev user,id=wan0 \
      -device virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57 \
      -netdev user,id=lan0 \
      -append "console=ttyAMA0,115200 root=/dev/ram0 rdinit=/init quiet net.ifnames=0" \
      -nographic
else
    echo "[qemu] ERROR: Unsupported architecture: $ARCH"
    exit 1
fi
