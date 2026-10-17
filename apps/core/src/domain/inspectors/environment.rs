/*
 * File: environment.rs                                                        *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\environment.rs *
 * Project: inspectors                                                         *
 * Author: pi-maaster77                                                        *
 * Created Date: Sa/10/2026 03:45:28                                           *
 * Last Modified: Sat Oct 17 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

//! Reconciles persistent Windows environment variables against the exact Nickel allowlist.
//! Undeclared values are deleted, declared values are restored, and logs contain hashes only.

use crate::config::inspectors::EnvironmentPolicy;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

const SYSTEM_ENVIRONMENT_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const USER_ENVIRONMENT_KEY: &str = "Environment";
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Starts the environment monitor and stops it when Ctrl+C is received.
pub fn inspect(policy: &EnvironmentPolicy) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let handler_running = Arc::clone(&running);
    let monitor_thread = thread::current();
    ctrlc::set_handler(move || {
        handler_running.store(false, Ordering::Relaxed);
        monitor_thread.unpark();
    })
    .context("no se pudo registrar el manejador de Ctrl+C")?;

    inspect_until_stopped(policy, running.as_ref())
}

/// Monitors and reconciles both registry scopes until `running` becomes false.
pub fn inspect_until_stopped(policy: &EnvironmentPolicy, running: &AtomicBool) -> Result<()> {
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let user = RegKey::predef(HKEY_CURRENT_USER);
    let mut system_snapshot =
        reconcile_and_read("system", &machine, SYSTEM_ENVIRONMENT_KEY, &policy.system)?;
    let mut user_snapshot = reconcile_and_read("user", &user, USER_ENVIRONMENT_KEY, &policy.user)?;

    log_snapshot("system", &system_snapshot);
    log_snapshot("user", &user_snapshot);
    info!(
        poll_interval_seconds = POLL_INTERVAL.as_secs(),
        "Monitoreo de entorno activo; Ctrl+C para detener."
    );

    while running.load(Ordering::Relaxed) {
        thread::park_timeout(POLL_INTERVAL);
        if !running.load(Ordering::Relaxed) {
            break;
        }

        refresh_scope(
            "system",
            &machine,
            SYSTEM_ENVIRONMENT_KEY,
            &policy.system,
            &mut system_snapshot,
        );
        refresh_scope(
            "user",
            &user,
            USER_ENVIRONMENT_KEY,
            &policy.user,
            &mut user_snapshot,
        );
    }

    info!("Monitoreo de entorno detenido.");
    Ok(())
}

fn read_scope_from_key(scope: &str, key: &RegKey) -> Result<BTreeMap<String, String>> {
    let mut snapshot = BTreeMap::new();
    for entry in key.enum_values() {
        let (name, _) = entry.with_context(|| format!("no se pudo enumerar el entorno {scope}"))?;
        let value: String = key
            .get_value(&name)
            .with_context(|| format!("no se pudo leer la variable {name} del entorno {scope}"))?;
        snapshot.insert(name, value);
    }
    Ok(snapshot)
}

fn reconcile_and_read(
    scope: &str,
    root: &RegKey,
    subkey: &str,
    allowed: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let key = root
        .open_subkey_with_flags(subkey, KEY_READ | KEY_SET_VALUE)
        .with_context(|| format!("se requieren permisos de escritura para el entorno {scope}"))?;
    let current = read_scope_from_key(scope, &key)?;

    for action in plan_reconciliation(&current, allowed) {
        match action {
            ReconciliationAction::Delete(name) => {
                warn!(scope, variable = %name, action = "delete", "Variable no declarada en Nickel; se elimina.");
                key.delete_value(&name).with_context(|| {
                    format!("no se pudo eliminar la variable {name} de {scope}")
                })?;
            }
            ReconciliationAction::Set(name, value) => {
                if let Some((_, previous_value)) = find_variable(&current, &name) {
                    warn!(
                        scope,
                        variable = %name,
                        previous_sha256 = %hash_value(previous_value),
                        value_sha256 = %hash_value(&value),
                        action = "restore",
                        "Valor distinto de Nickel; se restaura el valor declarado."
                    );
                } else {
                    warn!(
                        scope,
                        variable = %name,
                        value_sha256 = %hash_value(&value),
                        action = "restore",
                        "Variable declarada en Nickel; se repone."
                    );
                }
                key.set_value(&name, &value).with_context(|| {
                    format!("no se pudo restaurar la variable {name} de {scope}")
                })?;
            }
        }
    }

    read_scope_from_key(scope, &key)
}

#[derive(Debug, PartialEq, Eq)]
enum ReconciliationAction {
    Delete(String),
    Set(String, String),
}

fn plan_reconciliation(
    current: &BTreeMap<String, String>,
    allowed: &BTreeMap<String, String>,
) -> Vec<ReconciliationAction> {
    let mut actions = Vec::new();

    for (name, value) in current {
        match find_variable(allowed, name) {
            None => actions.push(ReconciliationAction::Delete(name.clone())),
            Some((declared_name, declared_value)) if value != declared_value => {
                actions.push(ReconciliationAction::Set(
                    declared_name.clone(),
                    declared_value.clone(),
                ));
            }
            Some(_) => {}
        }
    }

    for (declared_name, declared_value) in allowed {
        if find_variable(current, declared_name).is_none() {
            actions.push(ReconciliationAction::Set(
                declared_name.clone(),
                declared_value.clone(),
            ));
        }
    }

    actions
}

fn find_variable<'a>(
    variables: &'a BTreeMap<String, String>,
    name: &str,
) -> Option<(&'a String, &'a String)> {
    variables
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
}

fn log_snapshot(scope: &str, snapshot: &BTreeMap<String, String>) {
    for (name, value) in snapshot {
        info!(
            scope,
            variable = %name,
            value_sha256 = %hash_value(value),
            "Variable de entorno inventariada."
        );
    }
    info!(
        scope,
        variables = snapshot.len(),
        "Snapshot de entorno capturado."
    );
}

fn refresh_scope(
    scope: &str,
    root: &RegKey,
    subkey: &str,
    allowed: &BTreeMap<String, String>,
    previous: &mut BTreeMap<String, String>,
) {
    match reconcile_and_read(scope, root, subkey, allowed) {
        Ok(current) => {
            log_changes(scope, previous, &current);
            *previous = current;
        }
        Err(error) => {
            error!(scope, error = %error, "Falló la reconciliación de variables de entorno.")
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ChangeKind {
    Added,
    Changed,
    Removed,
}

#[derive(Debug, PartialEq, Eq)]
struct VariableChange {
    name: String,
    kind: ChangeKind,
}

fn diff_snapshots(
    previous: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) -> Vec<VariableChange> {
    let mut changes = Vec::new();

    for (name, previous_value) in previous {
        match current.get(name) {
            None => changes.push(VariableChange {
                name: name.clone(),
                kind: ChangeKind::Removed,
            }),
            Some(value) if value != previous_value => changes.push(VariableChange {
                name: name.clone(),
                kind: ChangeKind::Changed,
            }),
            Some(_) => {}
        }
    }

    for name in current.keys() {
        if !previous.contains_key(name) {
            changes.push(VariableChange {
                name: name.clone(),
                kind: ChangeKind::Added,
            });
        }
    }

    changes
}

fn log_changes(
    scope: &str,
    previous: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) {
    for change in diff_snapshots(previous, current) {
        match change.kind {
            ChangeKind::Added => info!(
                scope,
                variable = %change.name,
                value_sha256 = %hash_value(&current[&change.name]),
                change = "added",
                "Cambio en variable de entorno."
            ),
            ChangeKind::Changed => info!(
                scope,
                variable = %change.name,
                previous_sha256 = %hash_value(&previous[&change.name]),
                value_sha256 = %hash_value(&current[&change.name]),
                change = "changed",
                "Cambio en variable de entorno."
            ),
            ChangeKind::Removed => info!(
                scope,
                variable = %change.name,
                previous_sha256 = %hash_value(&previous[&change.name]),
                change = "removed",
                "Cambio en variable de entorno."
            ),
        }
    }
}

fn hash_value(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut hash = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hash, "{byte:02x}");
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{
        diff_snapshots, hash_value, plan_reconciliation, ChangeKind, ReconciliationAction,
        VariableChange,
    };
    use std::collections::BTreeMap;

    #[test]
    fn value_hash_is_stable_and_does_not_expose_the_value() {
        let hash = hash_value("example-secret");
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains("example-secret"));
    }

    #[test]
    fn snapshots_classify_added_changed_and_removed_variables() {
        let previous = BTreeMap::from([
            ("KEEP".to_string(), "same".to_string()),
            ("CHANGE".to_string(), "before".to_string()),
            ("REMOVE".to_string(), "gone".to_string()),
        ]);
        let current = BTreeMap::from([
            ("KEEP".to_string(), "same".to_string()),
            ("CHANGE".to_string(), "after".to_string()),
            ("ADD".to_string(), "new".to_string()),
        ]);

        assert_eq!(
            diff_snapshots(&previous, &current),
            vec![
                VariableChange {
                    name: "CHANGE".to_string(),
                    kind: ChangeKind::Changed,
                },
                VariableChange {
                    name: "REMOVE".to_string(),
                    kind: ChangeKind::Removed,
                },
                VariableChange {
                    name: "ADD".to_string(),
                    kind: ChangeKind::Added,
                },
            ]
        );
    }

    #[test]
    fn empty_allowlist_plans_deletion_of_every_variable() {
        let current = BTreeMap::from([
            ("Path".to_string(), "system-path".to_string()),
            ("TEMP".to_string(), "temp-dir".to_string()),
        ]);

        assert_eq!(
            plan_reconciliation(&current, &BTreeMap::new()),
            vec![
                ReconciliationAction::Delete("Path".to_string()),
                ReconciliationAction::Delete("TEMP".to_string()),
            ]
        );
    }

    #[test]
    fn reconciliation_restores_changes_and_missing_declared_values() {
        let current = BTreeMap::from([
            ("Path".to_string(), "tampered".to_string()),
            ("REMOVE".to_string(), "not-allowed".to_string()),
        ]);
        let allowed = BTreeMap::from([
            ("PATH".to_string(), "declared-path".to_string()),
            ("MODE".to_string(), "strict".to_string()),
        ]);

        assert_eq!(
            plan_reconciliation(&current, &allowed),
            vec![
                ReconciliationAction::Set("PATH".to_string(), "declared-path".to_string()),
                ReconciliationAction::Delete("REMOVE".to_string()),
                ReconciliationAction::Set("MODE".to_string(), "strict".to_string()),
            ]
        );
    }
}
