/*
 * File: registry.rs                                                           *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\environment\registry.rs *
 * Project: environment                                                        *
 * Author: pi-maaster77                                                        *
 * Created Date: Mo/10/2026 01:20:52                                           *
 * Last Modified: Thu Oct 22 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use super::diff::hash_value;
use super::plan::{find_variable, plan_reconciliation, ReconciliationAction};
use crate::config::inspectors::EnvironmentPolicy;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::warn;
use winreg::enums::{KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

pub(super) const SYSTEM_ENVIRONMENT_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
pub(super) const USER_ENVIRONMENT_KEY: &str = "Environment";
pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub(super) fn read_scope_from_key(scope: &str, key: &RegKey) -> Result<BTreeMap<String, String>> {
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

pub(super) fn reconcile_and_read(
    scope: &str,
    root: &RegKey,
    subkey: &str,
    policy: &EnvironmentPolicy,
    allowed: &BTreeMap<String, String>,
    delete_names: &[String],
) -> Result<BTreeMap<String, String>> {
    let key = root
        .open_subkey_with_flags(subkey, KEY_READ | KEY_SET_VALUE)
        .with_context(|| format!("se requieren permisos de escritura para el entorno {scope}"))?;
    let current = read_scope_from_key(scope, &key)?;

    for action in plan_reconciliation(
        &current,
        allowed,
        delete_names,
        policy.mode,
        policy.allow_destructive,
    ) {
        match action {
            ReconciliationAction::Delete(name) => {
                warn!(scope, variable = %name, action = "delete", "Variable eliminada por la política de entorno.");
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
