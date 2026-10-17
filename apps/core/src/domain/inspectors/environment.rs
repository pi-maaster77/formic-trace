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
use tracing::{error, info};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

const SYSTEM_ENVIRONMENT_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const USER_ENVIRONMENT_KEY: &str = "Environment";
const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub fn inspect() -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let handler_running = Arc::clone(&running);
    let monitor_thread = thread::current();
    ctrlc::set_handler(move || {
        handler_running.store(false, Ordering::Relaxed);
        monitor_thread.unpark();
    })
    .context("no se pudo registrar el manejador de Ctrl+C")?;

    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let user = RegKey::predef(HKEY_CURRENT_USER);
    let mut system_snapshot = read_scope("system", &machine, SYSTEM_ENVIRONMENT_KEY)?;
    let mut user_snapshot = read_scope("user", &user, USER_ENVIRONMENT_KEY)?;

    log_snapshot("system", &system_snapshot);
    log_snapshot("user", &user_snapshot);
    info!(
        poll_interval_seconds = POLL_INTERVAL.as_secs(),
        "Monitoreo de entorno iniciado; Ctrl+C para detener."
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
            &mut system_snapshot,
        );
        refresh_scope("user", &user, USER_ENVIRONMENT_KEY, &mut user_snapshot);
    }

    info!("Monitoreo de entorno detenido.");
    Ok(())
}

fn read_scope(scope: &str, root: &RegKey, subkey: &str) -> Result<BTreeMap<String, String>> {
    let key = root
        .open_subkey_with_flags(subkey, KEY_READ)
        .with_context(|| format!("no se pudo abrir la clave de entorno {scope}"))?;
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
    previous: &mut BTreeMap<String, String>,
) {
    match read_scope(scope, root, subkey) {
        Ok(current) => {
            log_changes(scope, previous, &current);
            *previous = current;
        }
        Err(error) => {
            error!(scope, error = %error, "No se pudo actualizar el snapshot de entorno.")
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
            ChangeKind::Added => {
                let value = &current[&change.name];
                info!(
                    scope,
                    variable = %change.name,
                    value_sha256 = %hash_value(value),
                    change = "added",
                    "Cambio en variable de entorno."
                );
            }
            ChangeKind::Changed => {
                let previous_value = &previous[&change.name];
                let value = &current[&change.name];
                info!(
                    scope,
                    variable = %change.name,
                    previous_sha256 = %hash_value(previous_value),
                    value_sha256 = %hash_value(value),
                    change = "changed",
                    "Cambio en variable de entorno."
                );
            }
            ChangeKind::Removed => {
                let previous_value = &previous[&change.name];
                info!(
                    scope,
                    variable = %change.name,
                    previous_sha256 = %hash_value(previous_value),
                    change = "removed",
                    "Cambio en variable de entorno."
                );
            }
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
    use super::{diff_snapshots, hash_value, ChangeKind, VariableChange};
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
}
