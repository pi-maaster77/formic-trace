# Agent Instructions

## Project

- This is the Formic Windows security workspace, primarily Rust, with Nickel configuration.
- The active Cargo workspace includes `apps/core` and `libs/windows-features`.
- Read `README.md` and `docs/architecture.md` when changing runtime or configuration behavior.

## Build and Tests

- Use the explicitly selected stable toolchain in this environment:
  - `cargo +stable check -p formic-core`
  - `cargo +stable test -p formic-core`
  - `cargo +stable test -p windows-features --lib`
  - `cargo +stable build -p formic-core`
- Prefer focused package tests after a narrow change, then run the relevant broader tests.
- Format only the files changed for a task; workspace-wide `cargo fmt --all -- --check` currently reports pre-existing formatting differences in unrelated files.
- The Rust Analyzer toolchain must match the toolchain used to build proc macros. If macro errors report a rustc version mismatch, align Rust Analyzer and Cargo rather than changing source code.

## Windows and DISM Safety

- `apps/core` has `#![forbid(unsafe_code)]`. Keep Windows API unsafe code inside `libs/windows-features`.
- Keep DISM FFI declarations aligned with the Windows SDK prototypes and structure layouts. The DISM feature-state numeric mapping and four-byte struct packing have regression tests; update those tests when changing the FFI.
- `--inspect-system-features` can enable, disable, install, or remove Windows features according to policy. Do not run it elevated unless the user explicitly requests a runtime test and understands those system changes.
- `--dump-features` only inventories DISM state, but requires access to the online DISM session. It writes `config/inspectors/system_features/features.toml` and overwrites that file.

## System Feature Policy

- `config/inspectors/system_features/default.ncl` imports `features.toml`; keep policy values boolean (`true` or `false`).
- A feature or capability absent from the imported Nickel maps is unmanaged and must remain unchanged.
- The TOML dump translates DISM states to booleans. Preserve the authoritative DISM enum mapping; do not serialize transient labels such as `staged` or `pending` as desired policy values.
- DISM can report that an operation requires a reboot. Preserve that distinction in the result and logs; a successful HRESULT without the reboot-required code means DISM did not request a reboot.

## Change Discipline

- Keep changes scoped to the owning module and preserve existing public APIs unless the task requires otherwise.
- Inspect current file contents before editing, especially files the user or formatter may have changed.
- Do not overwrite user-authored policy data with generated output without explicit user intent. Treat `features.toml` as user-editable because `--dump-features` replaces it.
- Do not run feature-enabling or feature-removing commands as part of ordinary tests.
