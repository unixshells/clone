# Clone Makefile
#
# Quick start (on a Linux KVM machine):
#   make all              Build + unit tests + e2e tests (one command)
#   make build            Build release binary
#   make test             Run unit tests
#   make e2e              Run full end-to-end tests (requires Linux + KVM + root)
#   make clean            Clean build artifacts
#
# Selective e2e:
#   make e2e-quick        Boot + control socket smoke tests only
#   make e2e-snapshot     Snapshot / fork / CoW / incremental tests
#   make e2e-storage      Virtio-block + QCOW2 tests
#   make e2e-security     Seccomp + template integrity tests
#   make e2e-migration    Live migration test
#   make e2e-devices      Virtio-fs + PCI bus + VFIO passthrough tests
#   make e2e-multivm      Concurrent VMs + memory accounting tests
#
# Environment variables:
#   KERNEL=/path/to/vmlinuz   Override kernel for e2e tests (6.5+ required, 5.15 has bugs)
#   CLONE=/path/to/clone    Override binary path

.PHONY: all build build-debug test check fmt clippy \
        e2e e2e-quick e2e-boot e2e-snapshot e2e-storage e2e-security \
        e2e-migration e2e-devices e2e-multivm \
        initrd clean

# ── Top-level ────────────────────────────────────────────────────────────

all: build test e2e

# ── Build ────────────────────────────────────────────────────────────────

build:
	cargo build --release

build-debug:
	cargo build

# ── Unit tests ───────────────────────────────────────────────────────────

test:
	cargo test

check:
	cargo check

fmt:
	cargo fmt -- --check

clippy:
	cargo clippy -- -D warnings

# ── End-to-end tests ────────────────────────────────────────────────────
# All e2e targets require: Linux, KVM (/dev/kvm), root (sudo), busybox-static

E2E_ENV = CLONE=$(PWD)/target/release/clone $(if $(KERNEL),KERNEL=$(KERNEL),)

e2e: build
	@echo "══════════════════════════════════════════════"
	@echo " Running full e2e test suite"
	@echo " Requires: Linux + KVM + root + busybox-static"
	@echo "══════════════════════════════════════════════"
	sudo $(E2E_ENV) ./tests/e2e/run_all.sh

e2e-quick: build
	@echo "Running quick smoke tests..."
	sudo $(E2E_ENV) ./tests/e2e/run_all.sh test_boot_serial test_control_socket

e2e-boot: build
	@echo "Running boot speed tests..."
	sudo $(E2E_ENV) ./tests/e2e/run_all.sh \
		test_boot_speed test_boot_speed_avg test_acpi_no_errors

e2e-snapshot: build
	@echo "Running snapshot/fork/CoW tests..."
	sudo $(E2E_ENV) ./tests/e2e/run_all.sh \
		test_snapshot_fork test_incremental_snapshot test_cow_memory_sharing

e2e-storage: build
	@echo "Running storage tests..."
	sudo $(E2E_ENV) ./tests/e2e/run_all.sh \
		test_virtio_block_rw test_qcow2_block test_qcow2_backing_file

e2e-security: build
	@echo "Running security tests..."
	sudo $(E2E_ENV) ./tests/e2e/run_all.sh \
		test_seccomp_filter test_template_integrity

e2e-migration: build
	@echo "Running live migration test..."
	sudo $(E2E_ENV) ./tests/e2e/run_all.sh \
		test_live_migration

e2e-devices: build
	@echo "Running device tests (virtio-fs, PCI, VFIO)..."
	sudo $(E2E_ENV) ./tests/e2e/run_all.sh \
		test_virtiofs test_pci_bus test_vfio_passthrough

e2e-multivm: build
	@echo "Running multi-VM tests..."
	sudo $(E2E_ENV) ./tests/e2e/run_all.sh \
		test_concurrent_vms test_memory_accounting

# ── Helpers ──────────────────────────────────────────────────────────────

initrd:
	./scripts/make_initrd.sh

# ── Clean ────────────────────────────────────────────────────────────────

clean:
	cargo clean
	rm -f /tmp/clone-e2e-*
	rm -f /tmp/clone-initrd-*
