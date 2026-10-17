# Formic Core: Architecture and Configuration

## Runtime Flow

`apps/core/src/main.rs` parses CLI arguments and selects calibration or inspection. The `#![forbid(unsafe_code)]` crate attribute prevents unsafe blocks in the Formic core; operating-system details are delegated to dependencies such as `schannel`.

The inspection path evaluates `config/default.ncl` in process through the stable `nickel-lang` library. The interpreter resolves relative imports from the canonical source path, evaluates contracts deeply, and deserializes the resulting expression into Rust structs. `apps/core/src/config/inspectors.rs` validates policy invariants before passing the typed config to `apps/core/src/domain/inspectors/certs.rs`. Configuration-load errors are retained and logged after the component logger is initialized; the fallback policy is `alert_only` with no imports.

The certificate inspector opens `LocalMachine\\Root` through Schannel, inventories certificates, computes SHA-256 fingerprints and issuer-name hashes, then applies the configured policy. Enumeration is collected before deletion to avoid mutating the store iterator. Importing files is a separate operation and never occurs unless both `allow_import` and `allow_destructive` are true.

The environment inspector is an explicit CLI operation (`formic-core --inspect-environment`); normal runtime starts it alongside the certificate inspector. Nickel declares exact machine and current-user values in `config/inspectors/environment/default.ncl`. At startup and every second, the monitor deletes undeclared variables and restores declared variables that were removed or changed; logs contain hashes, never values. The example declares `PRUEBA = "ESTOESUNAPRUEBA"` for the current user. The policy is authoritative: omitting a variable means it will be deleted. Machine-scope writes require elevated permissions, and the user scope is the account running Formic. Existing process environment blocks are not updated. Press `Ctrl+C` to stop monitoring. A future `SYSTEM` service will need a user-session handler and authenticated IPC for the interactive user's hive.

## Repository Map

- `apps/core/src/cli/`: command-line arguments, including the Nickel config path.
- `apps/core/src/config/`: deserialize Nickel's exported data and validate policy invariants.
- `apps/core/src/domain/inspectors/`: runtime inspectors; certificate-store operations live in `certs.rs`.
- `apps/core/src/domain/inspectors/environment.rs`: read-only inventory of persistent machine and current-user environment variables.
- `apps/core/src/engine/calibrate/`: read-only capture of the root-store SHA-256 baseline.
- `apps/core/src/logger.rs`: component log files under `logs/` and stdout tracing.
- `config/default.ncl`: imports the per-inspector and per-policy Nickel files.
- `config/inspectors/`: inspector settings. Hardware, identity and system-feature subtrees compose their child configs.
- `config/policies/`: policy settings grouped by domain.
- `config/inspectors/certs/third_party/`: explicitly enumerated external certificate inputs.

The non-certificate Nickel files currently provide configuration structure; they do not imply that the corresponding Rust inspectors are implemented or enforcing those values.

## Certificate Import Contract

The certificate preset is `config/inspectors/certs/default.ncl`. It defaults to `alert_only`, `allow_import = false`, and an empty import list. Import paths are strings relative to `config/inspectors/certs/` and must resolve beneath `third_party/`; supported extensions are `.cer`, `.crt`, and `.pem`, with one certificate per file.

Imports require both explicit flags. CA certificates must be valid at the current time. A non-CA certificate is accepted only when its subject equals its issuer and its signature verifies with its own public key. This supports deliberate self-signed test anchors, but trusting one changes Windows trust and is dangerous outside an isolated test machine. `alert_only` may be combined with an explicitly authorized import: it disables policy-driven deletion, not this separate import operation.

`alert_only` disables policy-driven deletion. An explicit import is an independent trust-store mutation and can still occur when both import flags are set. `minimal`, `whitelist`, `blacklist`, and `purge_all` are destructive policy modes and require review before use.

## Local Verification

From the repository root, compile and run tests with `cargo test -p formic-core`, then run `cargo run -p formic-core` and inspect `logs/certs/current.log`. The embedded Nickel interpreter requires no separate executable. `nickel export config/default.ncl` is an optional manual check. Nickel array entries for paths must be quoted strings. Fallback logs report why configuration was rejected and which mode is active. The included `test_malicious.cer` is a self-signed non-CA fixture; import it only on an isolated test machine.