use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use tracing::info;

pub(super) fn log_snapshot(scope: &str, snapshot: &BTreeMap<String, String>) {
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

pub(super) fn log_changes(
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

pub(super) fn hash_value(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut hash = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hash, "{byte:02x}");
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
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
