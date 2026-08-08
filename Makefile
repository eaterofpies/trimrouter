# =========================================================================
# trimrouter main Makefile (Supports separate targets for each architecture)
# =========================================================================

.PHONY: all clean help \
        initramfs-x86_64 initramfs-arm64 initramfs-armhf \
        image-x86_64 image-arm64 image-armhf \
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

# Configuration override path (defaults to config/trimrouter.toml)
TRIMROUTER_CONFIG ?= config/trimrouter.toml

# Track changes in TRIMROUTER_CONFIG path variable
CONFIG_PATH_TRACKER := target/.config_path
$(shell mkdir -p target)
OLD_CONFIG_PATH := $(shell cat $(CONFIG_PATH_TRACKER) 2>/dev/null)
ifneq ($(OLD_CONFIG_PATH),$(TRIMROUTER_CONFIG))
$(shell echo "$(TRIMROUTER_CONFIG)" > $(CONFIG_PATH_TRACKER))
endif

# Convenience default targets for host (x86_64)
all: image-x86_64

help:
	@echo "trimrouter build targets (Supported architectures: x86_64, arm64, armhf):"
	@echo ""
	@echo "  Host (x86_64)"
	@echo "    make / make all          Build static binary and VM image for x86_64"
	@echo ""
	@echo "  Architecture-specific"
	@echo "    make initramfs-<arch>    Build initramfs for a specific arch (x86_64, arm64, armhf)"
	@echo "    make image-<arch>        Build partitioned disk/SD image for a specific arch"
	@echo "    make qemu-<arch>         Boot VM image for a specific arch in QEMU"
	@echo "    make test-<arch>         Run integration tests for a specific arch"
	@echo ""
	@echo "  Configuration Overrides"
	@echo "    TRIMROUTER_CONFIG=path   Path to custom TOML config file (default: config/trimrouter.toml)"
	@echo ""
	@echo "  Misc"
	@echo "    make clean               Delete all build artifacts"

# =========================================================================
# Generic Architecture Rules Template
# =========================================================================
define ARCH_RULES
# $(1): Architecture (x86_64, arm64, armhf)

initramfs-$(1): target/$(1)/initramfs.cpio.gz
initramfs-test-$(1): target/$(1)/initramfs-test.cpio.gz

image-$(1): target/$(1)/trimrouter.img

qemu-$(1): target/$(1)/trimrouter.img
	@ARCH=$(1) ./test_qemu.sh

test-$(1): target/$(1)/trimrouter-test.img
	@echo "[test] Running integration tests for target architecture $(1)..."
	@TEST_ARCH=$(1) cargo test --test integration_test -- --nocapture

# Rule for building the target static binary
target/$(RUST_TARGET_$(1))/release/trimrouter: Cargo.toml Cargo.lock $(SRCS)
	@echo "[build] Ensuring $(RUST_TARGET_$(1)) target is installed..."
	@rustup target add $(RUST_TARGET_$(1))
	@echo "[build] Compiling trimrouter (Static $(1) Release)..."
	@RUSTFLAGS="-C linker-flavor=ld.lld -C linker=rust-lld" cargo build --release --target $(RUST_TARGET_$(1))

target/$(RUST_TARGET_$(1))/release/integration_test: Cargo.toml Cargo.lock $(SRCS)
	@echo "[build] Ensuring $(RUST_TARGET_$(1)) target is installed..."
	@rustup target add $(RUST_TARGET_$(1))
	@echo "[build] Compiling integration_test (Static $(1) Release)..."
	@RUSTFLAGS="-C linker-flavor=ld.lld -C linker=rust-lld" cargo build --release --bin integration_test --target $(RUST_TARGET_$(1))

# Rule for downloading and extracting Debian cloud kernel for tests
target/$(1)/test_boot/.kernel_extracted: scripts/extract_kernel.sh
	@./scripts/extract_kernel.sh $(1)

# Rule for building the target initramfs cpio archive
target/$(1)/initramfs.cpio.gz: target/$(RUST_TARGET_$(1))/release/trimrouter target/$(1)/test_boot/.kernel_extracted scripts/build_initramfs.sh
	@./scripts/build_initramfs.sh $(1) prod

target/$(1)/initramfs-test.cpio.gz: target/$(RUST_TARGET_$(1))/release/trimrouter target/$(RUST_TARGET_$(1))/release/integration_test target/$(1)/test_boot/.kernel_extracted scripts/build_initramfs.sh
	@./scripts/build_initramfs.sh $(1) test

# Rule for building the raw disk/SD image
target/$(1)/trimrouter.img: target/$(RUST_TARGET_$(1))/release/trimrouter target/$(1)/initramfs.cpio.gz scripts/build_image.sh $(TRIMROUTER_CONFIG) $(CONFIG_PATH_TRACKER)
	@./scripts/build_image.sh $(1) $(TRIMROUTER_CONFIG) trimrouter.img

# Rule for building the test raw disk image (always uses repository-default config/trimrouter.toml)
target/$(1)/trimrouter-test.img: target/$(RUST_TARGET_$(1))/release/trimrouter target/$(1)/initramfs-test.cpio.gz scripts/build_image.sh config/trimrouter.toml
	@./scripts/build_image.sh $(1) config/trimrouter.toml trimrouter-test.img
endef

# =========================================================================
# Instantiate templates
# =========================================================================
$(foreach arch,$(ARCHS),$(eval $(call ARCH_RULES,$(arch))))


# Clean build artifacts
clean:
	@echo "[clean] Cleaning all build targets and staging directories..."
	@cargo clean
	@rm -rf target/x86_64 target/arm64 target/armhf target/trimrouter.img target/trimrouter-test.img target/pi_boot target/.config_path
