---
name: commit-helper
description: Guidelines and instructions for running git commits securely and obtaining approval for git commit commands when the environment cancels context or denies permissions.
---

# Git Commit Helper Skill

This skill provides the instructions for performing git commits securely and resolving git command permission errors.

## 1. Commit Guidelines
* **Atomic & Working Commits**: Every individual commit must be self-contained, compile cleanly (`cargo check`), pass linter checks with zero warnings (`cargo clippy --all-targets`), and pass unit/integration tests (`cargo test`) independently. Never commit broken intermediate states that break `git bisect` or continuous integration.
* Always run pre-commit validation (`cargo check`, `cargo fmt --check`, `cargo clippy --all-targets`, and `cargo test`) before executing any commit.
* STRICT RULE: Never execute a git commit command without asking and obtaining explicit approval from the USER in the chat first.
* Format commit messages using Conventional Commits:
  * `feat: ...` for new features.
  * `fix: ...` for bug fixes.
  * `refactor: ...` for code cleanup.
  * `test: ...` for test suites.

## 2. Resolving Permission / Context Cancellation Errors
If a command like `git commit` fails with `permission check failed` or `context canceled`, it means the terminal sandbox or authorization layer blocked the command prefix. To resolve this:
* Always execute git subcommands directly with full, explicit argument flags (e.g. `git commit -m "..."`) rather than interactive or wrapped invocations.
* Note: Explicit user confirmation in chat remains strictly required before running any git commit command.