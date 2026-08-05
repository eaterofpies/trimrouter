#!/bin/bash
set -e

# =========================================================================
# QEMU Interactive Test Runner (Supports all architectures)
# =========================================================================
# Detect target architecture (defaults to x86_64)
ARCH=${ARCH:-x86_64}

# Ensure the kernel is downloaded and the VM image is compiled
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
    exec qemu-system-x86_64 \
      -m 256 \
      -kernel "$KERNEL" \
      -initrd "$INITRAMFS" \
      -append "console=ttyS0 quiet panic=-1 net.ifnames=0" \
      -drive file="$IMAGE",format=raw,media=disk,if=virtio \
      -netdev user,id=wan0,net=10.0.2.0/24 \
      -device virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56 \
      -netdev user,id=lan0,net=192.168.1.0/24 \
      -device virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57 \
      -nographic
elif [ "$ARCH" = "arm64" ]; then
    exec qemu-system-aarch64 \
      -M raspi3b \
      -cpu cortex-a53 \
      -m 1024 \
      -kernel "target/arm64/pi_boot/kernel8.img" \
      -dtb "target/arm64/pi_boot/bcm2710-rpi-3-b-plus.dtb" \
      -initrd "target/arm64/pi_initramfs.cpio.gz" \
      -drive file="$IMAGE",if=sd,format=raw \
      -device usb-net,netdev=lan0,mac=52:54:00:12:34:57 \
      -netdev user,id=lan0 \
      -append "console=ttyAMA0,115200 root=/dev/ram0 rdinit=/init quiet net.ifnames=0 dwc_otg.lpm_enable=0 dwc_otg.fiq_enable=0 dwc_otg.fiq_fsm_enable=0" \
      -nographic
elif [ "$ARCH" = "armhf" ]; then
    exec qemu-system-aarch64 \
      -M raspi3b \
      -cpu cortex-a53 \
      -m 1024 \
      -kernel "target/armhf/pi_boot/kernel.img" \
      -dtb "target/armhf/pi_boot/bcm2708-rpi-zero-w.dtb" \
      -initrd "target/armhf/pi_initramfs.cpio.gz" \
      -drive file="$IMAGE",if=sd,format=raw \
      -device usb-net,netdev=lan0,mac=52:54:00:12:34:57 \
      -netdev user,id=lan0 \
      -append "console=ttyAMA0,115200 root=/dev/ram0 rdinit=/init quiet net.ifnames=0 dwc_otg.lpm_enable=0 dwc_otg.fiq_enable=0 dwc_otg.fiq_fsm_enable=0" \
      -nographic
else
    echo "[qemu] ERROR: Unsupported architecture: $ARCH"
    exit 1
fi
