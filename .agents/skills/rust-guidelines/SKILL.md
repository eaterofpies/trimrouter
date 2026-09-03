---
name: rust-guidelines
description: Coding standards and guidelines for writing clean, flat, and idiomatic Rust code in this project, including package constants, no magic numbers, flat nesting, small functions, and aggressive code deduplication.
---

# Rust Coding Guidelines Skill

This skill provides code style and design standards for writing and modifying Rust code in the `trimrouter` repository.

## 1. Package Constants
* Avoid redefining protocol or system constants.
* Always import and use official constants from packages/crates (e.g., `dhcproto::v4::SERVER_PORT`, `dhcproto::v4::CLIENT_PORT`, `std::net::Ipv4Addr::BROADCAST`, `std::net::Ipv4Addr::UNSPECIFIED`).

## 2. Leverage Crates/Packages
* Prefer using existing library solutions over rolling custom implementations (e.g., using `ipnet` for parsing IP nets and calculating host scopes instead of bit-shifting IP octets).

## 3. No Magic Numbers
* Do not use raw literals for port numbers, offsets, flags, or configuration defaults.
* Declare `const` values at the module level or import them from standard libraries / external crates.

## 4. Indentation & Indentation Layer Limits
* **Strict nesting limit**: Indentation must be kept flat (ideally a maximum of 2 layers).
* **Count closures and spawned tasks**: Spawned tasks (e.g., `tokio::spawn(async move { ... })`), async blocks, and closures count toward the visual indentation nesting limit. Do not nest loops, matching blocks, or complex logic directly inside inline closures; extract them into dedicated top-level functions or methods instead.
* Eliminate arbitrary nested scope blocks.
* Refactor deep matching blocks, socket read/write setups, and complex state changes by extracting them into dedicated, flat functions.

## 5. Small, Single-Purpose Functions
* **Explicit Size Limits**: Write small, highly focused functions that perform a single task. Functions should not exceed **50 lines** of code (excluding comments and blank lines).
* **Nesting and Cognitive Limits**: Keep control flow nesting to a maximum of **2 layers**. Large event loops, nested `match`, or `if let` blocks must be decomposed by delegating to separate single-purpose helper functions.
* **Enforce via Clippy Lint**: Enable `#![deny(clippy::too_many_lines)]` at the crate level, or configure `too-many-lines-threshold = 50` in `clippy.toml` to catch oversized functions at build/test time.
* Deconstruct long event loops into simple sequential function calls.

## 6. Strict Error Handling
* **Never discard or swallow errors silently** (e.g. using `let _ = ...` or empty `catch`/`unwrap_or` blocks).
* **Avoid unconditional `unwrap()` or `expect()` calls** in production code, as they trigger abrupt panics. Prefer bubbling up errors using `Result` or `Option` mapping.
* **Wrap errors in custom error types** (e.g., custom error enums or `thiserror`-like types) where appropriate. This aids calling code with precise identification, categorization, and domain-specific error handling.
* Critical initialization and configuration errors (such as network interface configuration, packet parsing, or file mounting failures) must cause program failure or transition to a safe panic recovery reboot state rather than continuing in an undefined/broken state.

## 7. Aggressive Code Deduplication
* **Aggressively deduplicate code**. Avoid copy-pasting helper functions, boilerplate code, or duplicate logic patterns across different modules.
* Consolidate common behaviors (e.g., asynchronous task wait/shutdown logic, packet processing utility patterns, or socket configuration routines) into shared modules (such as `utils`) or common traits instead of repeating them.

## 8. Strong Typing at Boundaries (Early Symbolic Conversion & IPC Types)
* Parse and convert raw, weakly typed inputs (such as byte slices `&[u8]`, raw binary buffers, or strings) into strongly typed, domain-specific Rust structures (e.g., `pnet::util::MacAddr`, `std::net::Ipv4Addr`, or custom domain enums/structs) as early as possible (e.g., at network, parsing, or file boundaries).
* **Strongly Typed IPC Messages**: Use domain types (e.g., `MacAddr`, `Ipv4Addr`) directly in IPC message definitions rather than primitive byte arrays (e.g., `[u8; 6]`) or raw slices. Enable crate feature flags (e.g., `features = ["serde"]`) in `Cargo.toml` where necessary to support direct serialization across IPC boundaries.
* Avoid passing raw collections (like `&[u8]`, `Vec<u8>`, or generic `String`) down into core processing logic. Strongly typed symbolic boundaries prevent type-safety bypasses, eliminate redundant parser/formatter loops, and make calling interfaces self-documenting.

## 9. Top-of-File Imports Only & No Inline Path Qualification
* **Strict Rule: Top-of-File Imports Only (No Inner `use` Statements)**:
  * **Never** place `use` statements inside functions, methods, closures, match arms, or event loops.
  * **All** imports (`use ...;`) must be placed at the very top of the file, immediately after module-level inner attributes / doc comments and submodule declarations (`pub mod ...;`).
  * The **only exception** is inside isolated test submodules (e.g., `#[cfg(test)] mod tests { use super::*; }`).
  * If a function or modification requires a new type, trait, or extension (e.g., `Read`, `Write`, `CommandExt`), add it to the top-level import block first before using it.
* **Avoid Inline Path Qualification**:
  * Avoid using fully qualified paths (e.g., `crate::error::RouterError`, `std::collections::HashSet`, `std::sync::Mutex`, `std::os::unix::io::RawFd`) repeatedly inside function signatures or bodies.
  * Inline qualification should only be used where necessary to resolve name collisions (e.g., distinguishing `std::fmt::Error` from `std::io::Error`), or when using imports/aliases is less readable.

## 10. Pre-Commit Verification, Autoformatting & Working Commits
* **Working Commits Guarantee**: Every single git commit in a series must be self-contained and compile cleanly without errors or warnings. Never create intermediate commits that fail compilation or test suites.
* Run `cargo fmt` to ensure the codebase is formatted according to the standard style before staging changes.
* Run `cargo clippy --all-targets` and fix any warnings or errors before committing code. Warnings should be treated as errors where possible to maintain the highest code quality standards.
* Run `cargo test` to verify all unit and integration tests succeed on every commit.

## 11. Clean Option Logging
* **Avoid printing `Some(...)` in logs**: Whenever logging a message or diagnostic that contains an `Option` value, do not print it in its raw `Some(value)` representation.
* **Format Option values cleanly**: Output the value wrapped in quotes (e.g. `"10.0.2.15"`) if it is `Some`, or output `None` if it is empty. Use the `CleanOption` helper or implement custom `Debug`/`Display` manually on structs to formatting options cleanly.

## 12. Division of Concerns (Interface vs. Service)
* **Interface layer**: Only responsible for link administrative state management (bringing interfaces `UP` or `DOWN`) and executing services. It must not configure IP addresses or know about configurations.
* **Service layer** (e.g. `LanManager`, `DhcpClient`): Solely responsible for IP address assignment and management. Services must not transition link administrative states.
* **Generic Interfaces**: Keep the interface management structures (`ManagedInterface`) generic by injecting active services directly instead of branching on interface types.

## 13. Don't Make Unrelated Changes When Reorganising Code
* **Strict Separation of Structural Reorganisation and Logic Changes**: When reorganising directory layouts, renaming files, moving modules, or co-locating code (e.g., moving managers and workers into unified service folders), limit changes strictly to moving files, updating module paths, adjusting imports, and re-exporting symbols.
* **No Unrelated Refactors During Moves**: Do NOT modify algorithms, alter function signatures, change error handling behaviors, swap crates, or refactor unrelated logic as part of a reorganization.
* **One Change at a Time**: Perform architectural and structural reorganizations first in a dedicated, isolated commit. Any bug fixes, optimizations, or code cleanup must be performed in separate, focused follow-up commits.

## 14. Assertive Testing Standards (No Passive Smoke Tests)
* **Strict Assertion of Expected Behavior**: Tests must not merely check for the absence of panics or crashes (passive smoke testing). Every test must explicitly assert exact, correct domain behavior and contract compliance.
* **Tests Must Fail on Incorrect Logic**: Test assertions must be designed such that if the underlying algorithm, business logic, boundary handling, or timing calculations are wrong or suboptimal, the test **will fail immediately**.
* **Verify Negative & Edge Cases Actively**: Negative tests (such as malformed packets, truncated lengths, off-subnet gateways, or extreme timings) must explicitly verify that bad data is rejected, safely handled, or normalized to the specific expected outcome rather than blindly swallowed.

## 15. Full Version Number Pinning in `Cargo.toml`
* **Always Pin Full Version Numbers**: All dependencies and build-dependencies in `Cargo.toml` must always specify full three-component semantic version numbers (`major.minor.patch`, e.g., `version = "1.53.1"`, `version = "0.4.34"`, `version = "10.0.3"`).
* **No Partial Version Strings**: Never use truncated or partial versions such as `"1.53"`, `"0.4"`, or `"10"`. Full version numbers ensure deterministic dependency resolution and transparent auditing across builds.

## 16. No Duplicate String Literals (Named Constants for Strings)
* **Eliminate Repeated String Literals**: Do not scatter raw repeated string literals across functions, modules, or services (e.g., service identifiers like `"dns-forwarder"`, `"lan-manager"`, `"dhcp-client"`, `"dhcp-server"`, `"interface-monitor"`, sysfs paths, or configuration tags).
* **Declare Module or Crate-Level `const`**: Declare reusable strings as `pub const` at the module level or in a centralized definitions module (e.g., `crate::services` or `crate::network`), or use strongly typed symbolic representations (enums).
* **Consistency and Typo Prevention**: Using named constants ensures compile-time typo detection, simplifies audits, and guarantees single-point updates across supervisory, logging, IPC, and watchdog boundaries.

## 17. Single Canonical Constructors
* **Avoid Cascading `with_...` Constructor Permutations**: Do not proliferate intermediate constructors (e.g., `new`, `with_heartbeat`, `with_local_hosts`, `with_options`) across service structs.
* **Use Single Full Constructor**: Prefer a single, canonical constructor (`new(...)`) taking the required and optional parameters directly, or bundle optional parameters into a dedicated configuration/options struct.

## 18. Race-Free Service & Worker Startup Handshake
* **Explicit Startup Synchronization**: When a supervisor spawns a worker process that requires initial configuration (such as static leases or upstream resolvers), the worker must explicitly await and apply the initial IPC synchronization message before entering its main event loop or polling raw network sockets.
* **Prevent Early Traffic Processing**: Sockets must not service network requests before all initial configuration and exclusions have been loaded into active lookup tables.

