---
name: doc-sync
description: Guidelines and instructions to ensure that specifications (specs/), the README, and implementation code are fully synchronized and updated before committing changes.
---

# Document Synchronization Skill

This skill enforces strict rules to ensure documentation and code do not diverge during development.

## 1. Documentation Alignment Rules
*   **Zero Divergence**: Every commit that changes system behavior, configurations, networking parameters, or architecture must also update the corresponding specifications in `specs/` and the main `README.md`.
*   **No Stale Parameters**: If a kernel command-line parameter is added, modified, or removed in `src/config.rs` (e.g., `trimrouter.*`), verify it is documented immediately in both the `README.md` "Getting Started" section and the `specs/router_spec.md` Section 3 configuration list.
*   **Abstraction Integrity**:
    *   `specs/` should describe high-level architectures, requirements, workflows, and protocols. Avoid embedding explicit Rust implementation code blocks in specifications to prevent specs from breaking when internal variable names or code structures change.
    *   `README.md` must provide the high-level onboarding, features, prerequisites, building/packaging steps, and testing commands.

## 2. Pre-Commit Sync Verification Checklist
Before proposing or running a `git commit`:
1.  **Scan for Renames**: Check that all documents use the current project name `trimrouter` and contain no stale names.
2.  **Relative Link Verification**: Verify all markdown links are relative. Never use absolute paths (like `file:///workspaces/...` or `/workspaces/...`) which break on other host systems.
3.  **Auditing Code vs Docs**:
    *   Verify the Netfilter table/chain rules and library names in `specs/router_spec.md` match the current crate in `Cargo.toml` and implementation in `src/netfilter.rs`.
    *   Verify service lifecycles and injected dependency mappings in `specs/interface_di_spec.md` exactly align with the interface loop in `src/interface.rs`.
    *   Ensure the Raspberry Pi bootloader/initramfs paths in `specs/sd_card_image_spec.md` match the target output files built by the Makefile and packaging scripts.
