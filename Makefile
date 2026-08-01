# =========================================================================
# Trimrouter main Makefile (Supports separate targets for each architecture)
# =========================================================================

.PHONY: all clean qemu image test run-qemu help \
        initramfs-x86_64 initramfs-arm64 initramfs-armhf \
        qemu-x86_64 qemu-arm64 qemu-armhf \
        test-x86_64 test-arm64 test-armhf

# Architectures
ARCHS := x86_64 arm64 armhf

# Source files for dependency tracking
SRCS := $(shell find src -name "*.rs")

# Architecture mapping variables
RUST_TARGET_x86_64 := x86_64-unknown-linux-musl
RUST_TARGET_arm64  := aarch64-unknown-linux-musl
RUST_TARGET_armhf  := arm-unknown-linux-musleabihf

# Convenience default targets for host (x86_64)
all: initramfs-x86_64

qemu: qemu-x86_64
test: test-x86_64

help:
	@echo "trimrouter build targets (Supported architectures: x86_64, arm64, armhf):"
	@echo ""
	@echo "  Host (x86_64)"
	@echo "    make / make all          Build static binary and initramfs for x86_64"
	@echo "    make qemu                Boot x86_64 initramfs in QEMU"
	@echo "    make test                Run integration test suite against x86_64 QEMU VM"
	@echo ""
	@echo "  Raspberry Pi (arm64)"
	@echo "    make image               Build a bootable .img file for Raspberry Pi (arm64)"
	@echo "    make run-qemu            Boot the Raspberry Pi image in QEMU (-M raspi3b)"
	@echo ""
	@echo "  Architecture-specific"
	@echo "    make initramfs-<arch>    Build initramfs for a specific arch (x86_64, arm64, armhf)"
	@echo "    make qemu-<arch>         Boot initramfs for a specific arch in QEMU"
	@echo "    make test-<arch>         Run integration tests for a specific arch"
	@echo "    make image-<arch>        Build Raspberry Pi .img for a specific arch (arm64, armhf)"
	@echo "    make run-qemu-<arch>     Boot Raspberry Pi image for a specific arch in QEMU"
	@echo ""
	@echo "  Misc"
	@echo "    make clean               Delete all build artifacts"

# =========================================================================
# Generic Architecture Rules Template
# =========================================================================
define ARCH_RULES
# $(1): Architecture (x86_64, arm64, armhf)

initramfs-$(1): target/$(1)/initramfs.cpio.gz

qemu-$(1): target/$(1)/initramfs.cpio.gz
	@ARCH=$(1) ./test_qemu.sh

test-$(1): target/$(1)/initramfs.cpio.gz
	@echo "[test] Running integration tests for target architecture $(1)..."
	@TEST_ARCH=$(1) cargo test --test wan_dhcp_test -- --nocapture

# Rule for building the target static binary
target/$(RUST_TARGET_$(1))/release/trimrouter: Cargo.toml Cargo.lock $(SRCS)
	@echo "[build] Ensuring $(RUST_TARGET_$(1)) target is installed..."
	@rustup target add $(RUST_TARGET_$(1))
	@echo "[build] Compiling trimrouter (Static $(1) Release)..."
	@RUSTFLAGS="-C linker-flavor=ld.lld -C linker=rust-lld" cargo build --release --target $(RUST_TARGET_$(1))

# Rule for downloading and extracting Debian cloud kernel for tests
target/$(1)/test_boot/.kernel_extracted: scripts/extract_kernel.sh
	@./scripts/extract_kernel.sh $(1)

# Rule for building the target initramfs cpio archive
target/$(1)/initramfs.cpio.gz: target/$(RUST_TARGET_$(1))/release/trimrouter target/$(1)/test_boot/.kernel_extracted scripts/build_initramfs.sh
	@./scripts/build_initramfs.sh $(1)
endef

# =========================================================================
# Instantiate templates
# =========================================================================
$(foreach arch,$(ARCHS),$(eval $(call ARCH_RULES,$(arch))))

# Clean build artifacts
clean:
	@echo "[clean] Cleaning all build targets and staging directories..."
	@cargo clean
	@rm -rf target/x86_64 target/arm64 target/armhf target/trimrouter.img target/pi_boot

# Include Raspberry Pi deployment build rules
include Makefile.rpi
