/*
 * File: system_features.rs
 * Path: apps/core/src/domain/inspectors/system_features.rs
 * Project: inspectors
 * License: GNU General Public License v3.0 (GPLv3)
 */

//! Monitors Windows optional features and capabilities against Nickel policy.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};
use windows_features::{Capability, DismError, DismSession, Feature, FeatureState};

use crate::config::inspectors::{FeatureDesiredState, SystemFeaturesPolicy};

const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Snapshot of the Windows Optional Features and Capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemFeaturesSnapshot {
    pub features: BTreeMap<String, FeatureState>,
    pub capabilities: BTreeMap<String, FeatureState>,
}

#[derive(Serialize)]
struct FeatureInventory {
    optional_features: BTreeMap<String, bool>,
    capabilities: BTreeMap<String, bool>,
}

/// Exports the current Windows inventory without applying the Nickel policy.
pub fn dump_features(config_path: &Path) -> Result<PathBuf> {
    let session = DismSession::open_online().context("falló al abrir la sesión online de DISM")?;
    let snapshot = read_snapshot_from_session(&session)?;
    let output_path = feature_dump_path(config_path);
    let inventory = FeatureInventory {
        optional_features: snapshot
            .features
            .into_iter()
            .map(|(name, state)| (name, state.is_enabled_or_pending()))
            .collect(),
        capabilities: snapshot
            .capabilities
            .into_iter()
            .map(|(name, state)| (name, state.is_enabled_or_pending()))
            .collect(),
    };
    let contents = toml::to_string_pretty(&inventory)
        .context("no se pudo serializar el inventario de características a TOML")?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("no se pudo crear {}", parent.display()))?;
    }
    fs::write(&output_path, contents)
        .with_context(|| format!("no se pudo escribir {}", output_path.display()))?;

    Ok(output_path)
}

fn feature_dump_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("inspectors")
        .join("system_features")
        .join("features.toml")
}

/// Starts the system-features monitor and stops it on Ctrl+C.
pub fn inspect(policy: &SystemFeaturesPolicy) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let handler_running = Arc::clone(&running);
    let monitor_thread = thread::current();
    ctrlc::set_handler(move || {
        handler_running.store(false, Ordering::Relaxed);
        monitor_thread.unpark();
    })
    .context("no se pudo registrar el manejador de Ctrl+C para el inspector de características")?;

    inspect_until_stopped(policy, running.as_ref())
}

/// Monitors state transitions and reconciles only features that contradict policy.
pub fn inspect_until_stopped(policy: &SystemFeaturesPolicy, running: &AtomicBool) -> Result<()> {
    let mut snapshot = match reconcile_and_read(policy, None) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            warn!(error = %error, "No se pudo realizar el snapshot inicial de características (¿se requieren permisos de administrador?).");
            SystemFeaturesSnapshot::default()
        }
    };

    log_snapshot(&snapshot);
    info!(
        poll_interval_seconds = POLL_INTERVAL.as_secs(),
        "Monitoreo de características opcionales y capacidades activo; Ctrl+C para detener."
    );

    while running.load(Ordering::Relaxed) {
        thread::park_timeout(POLL_INTERVAL);
        if !running.load(Ordering::Relaxed) {
            break;
        }
        refresh_scope(policy, &mut snapshot);
    }

    info!("Monitoreo de características del sistema detenido.");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureAction {
    EnableFeature(String),
    DisableFeature(String),
    AddCapability(String),
    RemoveCapability(String),
}

/// Plans the initial reconciliation against every item listed in Nickel.
pub fn plan_reconciliation(
    snapshot: &SystemFeaturesSnapshot,
    policy: &SystemFeaturesPolicy,
) -> Vec<FeatureAction> {
    let mut actions = Vec::new();

    for (name, desired) in &policy.optional_features {
        let current = find_state_case_insensitive(&snapshot.features, name);
        match (desired, current) {
            (FeatureDesiredState::Enabled, Some(state)) if !state.is_enabled_or_pending() => {
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (FeatureDesiredState::Enabled, None) => {
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (FeatureDesiredState::Disabled, Some(state)) if state.is_enabled_or_pending() => {
                actions.push(FeatureAction::DisableFeature(name.clone()));
            }
            _ => {}
        }
    }

    for (name, desired) in &policy.capabilities {
        let current = find_state_case_insensitive(&snapshot.capabilities, name);
        match (desired, current) {
            (FeatureDesiredState::Enabled, Some(state)) if !state.is_enabled_or_pending() => {
                actions.push(FeatureAction::AddCapability(name.clone()));
            }
            (FeatureDesiredState::Enabled, None) => {
                actions.push(FeatureAction::AddCapability(name.clone()));
            }
            (FeatureDesiredState::Disabled, Some(state)) if state.is_enabled_or_pending() => {
                actions.push(FeatureAction::RemoveCapability(name.clone()));
            }
            _ => {}
        }
    }

    actions
}

fn find_state_case_insensitive<'a>(
    map: &'a BTreeMap<String, FeatureState>,
    target: &str,
) -> Option<&'a FeatureState> {
    map.iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(target))
        .map(|(_, state)| state)
}

fn find_desired_state(
    desired_states: &BTreeMap<String, FeatureDesiredState>,
    name: &str,
) -> Option<FeatureDesiredState> {
    desired_states
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, state)| *state)
}

fn plan_changed_reconciliation(
    previous: &SystemFeaturesSnapshot,
    current: &SystemFeaturesSnapshot,
    policy: &SystemFeaturesPolicy,
) -> Vec<FeatureAction> {
    let mut actions = Vec::new();

    for (name, current_state) in &current.features {
        let Some(previous_state) = find_state_case_insensitive(&previous.features, name) else {
            continue;
        };
        let was_enabled = previous_state.is_enabled_or_pending();
        let is_enabled = current_state.is_enabled_or_pending();
        if was_enabled == is_enabled {
            continue;
        }
        match (
            find_desired_state(&policy.optional_features, name),
            is_enabled,
        ) {
            (Some(FeatureDesiredState::Enabled), false) => {
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (Some(FeatureDesiredState::Disabled), true) => {
                actions.push(FeatureAction::DisableFeature(name.clone()));
            }
            _ => {}
        }
    }

    for (name, current_state) in &current.capabilities {
        let Some(previous_state) = find_state_case_insensitive(&previous.capabilities, name) else {
            continue;
        };
        let was_enabled = previous_state.is_enabled_or_pending();
        let is_enabled = current_state.is_enabled_or_pending();
        if was_enabled == is_enabled {
            continue;
        }
        match (find_desired_state(&policy.capabilities, name), is_enabled) {
            (Some(FeatureDesiredState::Enabled), false) => {
                actions.push(FeatureAction::AddCapability(name.clone()));
            }
            (Some(FeatureDesiredState::Disabled), true) => {
                actions.push(FeatureAction::RemoveCapability(name.clone()));
            }
            _ => {}
        }
    }

    actions
}

fn reconcile_and_read(
    policy: &SystemFeaturesPolicy,
    previous: Option<&SystemFeaturesSnapshot>,
) -> Result<SystemFeaturesSnapshot> {
    let session = match DismSession::open_online() {
        Ok(session) => session,
        Err(DismError::ElevationRequired) => {
            warn!("Se requieren permisos de Administrador para gestionar características opcionales de Windows.");
            return Ok(SystemFeaturesSnapshot::default());
        }
        Err(error) => return Err(error).context("falló al abrir la sesión online de DISM"),
    };

    let current = read_snapshot_from_session(&session)?;
    if let Some(previous) = previous {
        log_changes(previous, &current, policy);
    }
    let actions = match previous {
        Some(previous) => plan_changed_reconciliation(previous, &current, policy),
        None => plan_reconciliation(&current, policy),
    };

    for action in actions {
        match action {
            FeatureAction::EnableFeature(name) => {
                warn!(feature = %name, action = "enable", "La característica contradice la política de Nickel; se activa.");
                match session.enable_feature(&name, true) {
                    Ok(()) => {
                        info!(feature = %name, restart_required = false, "Característica habilitada; DISM no solicita reinicio.")
                    }
                    Err(DismError::RebootRequired) => {
                        info!(feature = %name, restart_required = true, "Característica habilitada; requiere reiniciar el equipo.")
                    }
                    Err(error) => {
                        error!(feature = %name, error = %error, "Fallo al habilitar la característica opcional.")
                    }
                }
            }
            FeatureAction::DisableFeature(name) => {
                warn!(feature = %name, action = "disable", "La característica contradice la política de Nickel; se desactiva.");
                match session.disable_feature(&name, false) {
                    Ok(()) => {
                        info!(feature = %name, restart_required = false, "Característica deshabilitada; DISM no solicita reinicio.")
                    }
                    Err(DismError::RebootRequired) => {
                        info!(feature = %name, restart_required = true, "Característica deshabilitada; requiere reiniciar el equipo.")
                    }
                    Err(error) => {
                        error!(feature = %name, error = %error, "Fallo al deshabilitar la característica opcional.")
                    }
                }
            }
            FeatureAction::AddCapability(name) => {
                warn!(capability = %name, action = "add", "La capacidad contradice la política de Nickel; se instala.");
                match session.add_capability(&name, false) {
                    Ok(()) => {
                        info!(capability = %name, restart_required = false, "Capacidad instalada; DISM no solicita reinicio.")
                    }
                    Err(DismError::RebootRequired) => {
                        info!(capability = %name, restart_required = true, "Capacidad agregada; requiere reiniciar el equipo.")
                    }
                    Err(error) => {
                        error!(capability = %name, error = %error, "Fallo al agregar la capacidad.")
                    }
                }
            }
            FeatureAction::RemoveCapability(name) => {
                warn!(capability = %name, action = "remove", "La capacidad contradice la política de Nickel; se quita.");
                match session.remove_capability(&name) {
                    Ok(()) => {
                        info!(capability = %name, restart_required = false, "Capacidad removida; DISM no solicita reinicio.")
                    }
                    Err(DismError::RebootRequired) => {
                        info!(capability = %name, restart_required = true, "Capacidad removida; requiere reiniciar el equipo.")
                    }
                    Err(error) => {
                        error!(capability = %name, error = %error, "Fallo al remover la capacidad.")
                    }
                }
            }
        }
    }

    let updated = read_snapshot_from_session(&session)?;
    log_changes(&current, &updated, policy);
    Ok(updated)
}

fn read_snapshot_from_session(session: &DismSession) -> Result<SystemFeaturesSnapshot> {
    let mut snapshot = SystemFeaturesSnapshot::default();
    for Feature { name, state } in session
        .get_features()
        .context("no se pudieron enumerar las características opcionales")?
    {
        snapshot.features.insert(name, state);
    }
    for Capability { name, state } in session
        .get_capabilities()
        .context("no se pudieron enumerar las capacidades (Features on Demand)")?
    {
        snapshot.capabilities.insert(name, state);
    }
    Ok(snapshot)
}

fn log_snapshot(snapshot: &SystemFeaturesSnapshot) {
    let active_features = snapshot
        .features
        .values()
        .filter(|state| state.is_enabled_or_pending())
        .count();
    let active_capabilities = snapshot
        .capabilities
        .values()
        .filter(|state| state.is_enabled_or_pending())
        .count();

    info!(
        total_features = snapshot.features.len(),
        active_or_pending_features = active_features,
        total_capabilities = snapshot.capabilities.len(),
        active_or_pending_capabilities = active_capabilities,
        "Snapshot de características y capacidades de Windows capturado."
    );
}

fn refresh_scope(policy: &SystemFeaturesPolicy, previous: &mut SystemFeaturesSnapshot) {
    match reconcile_and_read(policy, Some(previous)) {
        Ok(current) => *previous = current,
        Err(error) => {
            error!(error = %error, "Falló la reconciliación de características del sistema.")
        }
    }
}

fn log_changes(
    previous: &SystemFeaturesSnapshot,
    current: &SystemFeaturesSnapshot,
    policy: &SystemFeaturesPolicy,
) {
    for (name, current_state) in &current.features {
        if let Some(previous_state) = find_state_case_insensitive(&previous.features, name) {
            log_state_change(
                "Característica opcional",
                name,
                previous_state,
                current_state,
                find_desired_state(&policy.optional_features, name),
            );
        }
    }
    for (name, current_state) in &current.capabilities {
        if let Some(previous_state) = find_state_case_insensitive(&previous.capabilities, name) {
            log_state_change(
                "Capacidad de Windows",
                name,
                previous_state,
                current_state,
                find_desired_state(&policy.capabilities, name),
            );
        }
    }
}

fn log_state_change(
    kind: &str,
    name: &str,
    previous: &FeatureState,
    current: &FeatureState,
    desired: Option<FeatureDesiredState>,
) {
    if previous == current {
        return;
    }

    let was_enabled = previous.is_enabled_or_pending();
    let is_enabled = current.is_enabled_or_pending();
    match (was_enabled, is_enabled) {
        (false, true) => info!(
            item_type = kind,
            name,
            previous_state = ?previous,
            new_state = ?current,
            desired_state = ?desired,
            "Elemento activado."
        ),
        (true, false) => info!(
            item_type = kind,
            name,
            previous_state = ?previous,
            new_state = ?current,
            desired_state = ?desired,
            "Elemento desactivado."
        ),
        _ => info!(
            item_type = kind,
            name,
            previous_state = ?previous,
            new_state = ?current,
            desired_state = ?desired,
            "Cambió el estado del elemento."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_plan_reconciles_only_registered_items() {
        let snapshot = SystemFeaturesSnapshot {
            features: BTreeMap::from([
                ("FeatureA".to_string(), FeatureState::NotPresent),
                ("FeatureB".to_string(), FeatureState::Installed),
            ]),
            capabilities: BTreeMap::new(),
        };
        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::from([
                ("FeatureA".to_string(), FeatureDesiredState::Enabled),
                ("FeatureB".to_string(), FeatureDesiredState::Disabled),
            ]),
            capabilities: BTreeMap::new(),
        };

        assert_eq!(
            plan_reconciliation(&snapshot, &policy),
            vec![
                FeatureAction::EnableFeature("FeatureA".to_string()),
                FeatureAction::DisableFeature("FeatureB".to_string()),
            ]
        );
    }

    #[test]
    fn changed_plan_only_corrects_managed_transitions() {
        let previous = SystemFeaturesSnapshot {
            features: BTreeMap::from([
                ("managed-enabled".to_string(), FeatureState::Installed),
                ("managed-disabled".to_string(), FeatureState::NotPresent),
                ("unmanaged".to_string(), FeatureState::NotPresent),
            ]),
            capabilities: BTreeMap::new(),
        };
        let current = SystemFeaturesSnapshot {
            features: BTreeMap::from([
                ("managed-enabled".to_string(), FeatureState::NotPresent),
                ("managed-disabled".to_string(), FeatureState::Installed),
                ("unmanaged".to_string(), FeatureState::NotPresent),
            ]),
            capabilities: BTreeMap::new(),
        };
        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::from([
                ("managed-enabled".to_string(), FeatureDesiredState::Enabled),
                (
                    "managed-disabled".to_string(),
                    FeatureDesiredState::Disabled,
                ),
                ("unmanaged".to_string(), FeatureDesiredState::Enabled),
            ]),
            capabilities: BTreeMap::new(),
        };

        assert_eq!(
            plan_changed_reconciliation(&previous, &current, &policy),
            vec![
                FeatureAction::DisableFeature("managed-disabled".to_string()),
                FeatureAction::EnableFeature("managed-enabled".to_string()),
            ]
        );
    }

    #[test]
    fn dump_writes_boolean_values_next_to_policy_file() {
        let inventory = FeatureInventory {
            optional_features: BTreeMap::from([
                ("enabled-feature".to_string(), true),
                ("disabled-feature".to_string(), false),
            ]),
            capabilities: BTreeMap::new(),
        };
        let serialized = toml::to_string(&inventory).unwrap();
        let parsed: toml::Value = toml::from_str(&serialized).unwrap();

        assert_eq!(
            parsed["optional_features"]["enabled-feature"].as_bool(),
            Some(true)
        );
        assert_eq!(
            parsed["optional_features"]["disabled-feature"].as_bool(),
            Some(false)
        );
        assert_eq!(
            feature_dump_path(Path::new("config/default.ncl")),
            PathBuf::from("config/inspectors/system_features/features.toml")
        );
    }
}
