/*
 * File: system_features.rs                                                    *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\system_features.rs *
 * Project: inspectors                                                         *
 * Author: pi-maaster77                                                        *
 * Created Date: Su/10/2026                                                    *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

//! Reconciles Windows Optional Features (e.g. WSL, NetFx3, Hyper-V) and
//! Windows Capabilities / Features on Demand (e.g. OpenSSH, Internet Explorer)
//! against the declarative Nickel policy using the safe `windows-features` abstraction.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};
use windows_features::{
    Capability, DismError, DismSession, Feature, FeatureState,
};

use crate::config::inspectors::{FeatureDesiredState, SystemFeaturesPolicy};

const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Snapshot of the inventoried Windows Optional Features and Capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemFeaturesSnapshot {
    pub features: BTreeMap<String, FeatureState>,
    pub capabilities: BTreeMap<String, FeatureState>,
}

/// Starts the system features monitor and stops it when Ctrl+C is received.
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

/// Monitors and reconciles system features and capabilities until `running` becomes false.
pub fn inspect_until_stopped(policy: &SystemFeaturesPolicy, running: &AtomicBool) -> Result<()> {
    let mut snapshot = match reconcile_and_read(policy) {
        Ok(snap) => snap,
        Err(err) => {
            warn!(error = %err, "No se pudo realizar el snapshot inicial de características (¿se requieren permisos de administrador?).");
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

/// Represents an enforcement action planned to reconcile current state with policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureAction {
    EnableFeature(String),
    DisableFeature(String),
    AddCapability(String),
    RemoveCapability(String),
}

/// Plans reconciliation actions by comparing current state against declared policy.
pub fn plan_reconciliation(
    snapshot: &SystemFeaturesSnapshot,
    policy: &SystemFeaturesPolicy,
) -> Vec<FeatureAction> {
    let mut actions = Vec::new();

    // Reconcile Windows Optional Features
    for (name, desired) in &policy.optional_features {
        let current_state = find_state_case_insensitive(&snapshot.features, name);
        match (desired, current_state) {
            (FeatureDesiredState::Enabled, Some(state)) if !state.is_installed() => {
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (FeatureDesiredState::Enabled, None) => {
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (FeatureDesiredState::Disabled, Some(state)) if state.is_installed() => {
                actions.push(FeatureAction::DisableFeature(name.clone()));
            }
            _ => {}
        }
    }

    // Reconcile Windows Capabilities (Features on Demand)
    for (name, desired) in &policy.capabilities {
        let current_state = find_state_case_insensitive(&snapshot.capabilities, name);
        match (desired, current_state) {
            (FeatureDesiredState::Enabled, Some(state)) if !state.is_installed() => {
                actions.push(FeatureAction::AddCapability(name.clone()));
            }
            (FeatureDesiredState::Enabled, None) => {
                actions.push(FeatureAction::AddCapability(name.clone()));
            }
            (FeatureDesiredState::Disabled, Some(state)) if state.is_installed() => {
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

fn reconcile_and_read(policy: &SystemFeaturesPolicy) -> Result<SystemFeaturesSnapshot> {
    let session = match DismSession::open_online() {
        Ok(s) => s,
        Err(DismError::ElevationRequired) => {
            warn!("Se requieren permisos de Administrador para gestionar características opcionales de Windows.");
            return Ok(SystemFeaturesSnapshot::default());
        }
        Err(err) => return Err(err).context("falló al abrir la sesión online de DISM"),
    };

    let current = read_snapshot_from_session(&session)?;
    let actions = plan_reconciliation(&current, policy);

    for action in actions {
        match action {
            FeatureAction::EnableFeature(name) => {
                warn!(feature = %name, action = "enable", "Característica opcional deshabilitada o ausente; se habilita según política.");
                if let Err(err) = session.enable_feature(&name, true) {
                    if err == DismError::RebootRequired {
                        info!(feature = %name, "Característica habilitada; requiere reiniciar el equipo.");
                    } else {
                        error!(feature = %name, error = %err, "Fallo al habilitar la característica opcional.");
                    }
                }
            }
            FeatureAction::DisableFeature(name) => {
                warn!(feature = %name, action = "disable", "Característica opcional instalada no permitida; se deshabilita según política.");
                if let Err(err) = session.disable_feature(&name, false) {
                    if err == DismError::RebootRequired {
                        info!(feature = %name, "Característica deshabilitada; requiere reiniciar el equipo.");
                    } else {
                        error!(feature = %name, error = %err, "Fallo al deshabilitar la característica opcional.");
                    }
                }
            }
            FeatureAction::AddCapability(name) => {
                warn!(capability = %name, action = "add", "Capacidad requerida no instalada; se instala según política.");
                if let Err(err) = session.add_capability(&name, false) {
                    if err == DismError::RebootRequired {
                        info!(capability = %name, "Capacidad agregada; requiere reiniciar el equipo.");
                    } else {
                        error!(capability = %name, error = %err, "Fallo al agregar la capacidad.");
                    }
                }
            }
            FeatureAction::RemoveCapability(name) => {
                warn!(capability = %name, action = "remove", "Capacidad instalada no permitida; se remueve según política.");
                if let Err(err) = session.remove_capability(&name) {
                    if err == DismError::RebootRequired {
                        info!(capability = %name, "Capacidad removida; requiere reiniciar el equipo.");
                    } else {
                        error!(capability = %name, error = %err, "Fallo al remover la capacidad.");
                    }
                }
            }
        }
    }

    read_snapshot_from_session(&session)
}

fn read_snapshot_from_session(session: &DismSession) -> Result<SystemFeaturesSnapshot> {
    let mut snapshot = SystemFeaturesSnapshot::default();

    match session.get_features() {
        Ok(features) => {
            for Feature { name, state } in features {
                snapshot.features.insert(name, state);
            }
        }
        Err(err) => {
            warn!(error = %err, "No se pudieron enumerar las características opcionales");
        }
    }

    match session.get_capabilities() {
        Ok(capabilities) => {
            for Capability { name, state } in capabilities {
                snapshot.capabilities.insert(name, state);
            }
        }
        Err(err) => {
            warn!(error = %err, "No se pudieron enumerar las capacidades (Features on Demand)");
        }
    }

    Ok(snapshot)
}

fn log_snapshot(snapshot: &SystemFeaturesSnapshot) {
    let installed_features = snapshot
        .features
        .iter()
        .filter(|(_, state)| state.is_installed())
        .count();
    let installed_capabilities = snapshot
        .capabilities
        .iter()
        .filter(|(_, state)| state.is_installed())
        .count();

    info!(
        total_features = snapshot.features.len(),
        installed_features = installed_features,
        total_capabilities = snapshot.capabilities.len(),
        installed_capabilities = installed_capabilities,
        "Snapshot de características y capacidades de Windows capturado."
    );
}

fn refresh_scope(policy: &SystemFeaturesPolicy, previous: &mut SystemFeaturesSnapshot) {
    match reconcile_and_read(policy) {
        Ok(current) => {
            log_changes(previous, &current);
            *previous = current;
        }
        Err(error) => {
            error!(error = %error, "Falló la reconciliación de características del sistema.");
        }
    }
}

fn log_changes(previous: &SystemFeaturesSnapshot, current: &SystemFeaturesSnapshot) {
    for (name, curr_state) in &current.features {
        if let Some(prev_state) = previous.features.get(name) {
            if prev_state != curr_state {
                info!(
                    feature = %name,
                    previous_state = ?prev_state,
                    new_state = ?curr_state,
                    "Cambio de estado en característica opcional de Windows."
                );
            }
        }
    }

    for (name, curr_state) in &current.capabilities {
        if let Some(prev_state) = previous.capabilities.get(name) {
            if prev_state != curr_state {
                info!(
                    capability = %name,
                    previous_state = ?prev_state,
                    new_state = ?curr_state,
                    "Cambio de estado en capacidad de Windows."
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_reconciliation_enables_missing_features() {
        let mut snapshot = SystemFeaturesSnapshot::default();
        snapshot.features.insert(
            "Microsoft-Windows-Subsystem-Linux".to_string(),
            FeatureState::NotPresent,
        );
        snapshot
            .features
            .insert("NetFx3".to_string(), FeatureState::Installed);

        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::from([
                (
                    "Microsoft-Windows-Subsystem-Linux".to_string(),
                    FeatureDesiredState::Enabled,
                ),
                ("NetFx3".to_string(), FeatureDesiredState::Enabled),
            ]),
            capabilities: BTreeMap::new(),
        };

        let actions = plan_reconciliation(&snapshot, &policy);
        assert_eq!(
            actions,
            vec![FeatureAction::EnableFeature(
                "Microsoft-Windows-Subsystem-Linux".to_string()
            )]
        );
    }

    #[test]
    fn test_plan_reconciliation_disables_unwanted_features() {
        let mut snapshot = SystemFeaturesSnapshot::default();
        snapshot
            .features
            .insert("Hyper-V".to_string(), FeatureState::Installed);

        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::from([(
                "Hyper-V".to_string(),
                FeatureDesiredState::Disabled,
            )]),
            capabilities: BTreeMap::new(),
        };

        let actions = plan_reconciliation(&snapshot, &policy);
        assert_eq!(
            actions,
            vec![FeatureAction::DisableFeature("Hyper-V".to_string())]
        );
    }

    #[test]
    fn test_plan_reconciliation_handles_capabilities() {
        let mut snapshot = SystemFeaturesSnapshot::default();
        snapshot.capabilities.insert(
            "OpenSSH.Client~~~~0.0.1.0".to_string(),
            FeatureState::NotPresent,
        );
        snapshot.capabilities.insert(
            "OpenSSH.Server~~~~0.0.1.0".to_string(),
            FeatureState::Installed,
        );

        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::new(),
            capabilities: BTreeMap::from([
                (
                    "OpenSSH.Client~~~~0.0.1.0".to_string(),
                    FeatureDesiredState::Enabled,
                ),
                (
                    "OpenSSH.Server~~~~0.0.1.0".to_string(),
                    FeatureDesiredState::Disabled,
                ),
            ]),
        };

        let actions = plan_reconciliation(&snapshot, &policy);
        assert_eq!(
            actions,
            vec![
                FeatureAction::AddCapability("OpenSSH.Client~~~~0.0.1.0".to_string()),
                FeatureAction::RemoveCapability("OpenSSH.Server~~~~0.0.1.0".to_string()),
            ]
        );
    }

    #[test]
    fn test_case_insensitive_feature_matching() {
        let mut snapshot = SystemFeaturesSnapshot::default();
        snapshot
            .features
            .insert("netfx3".to_string(), FeatureState::Installed);

        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::from([(
                "NetFx3".to_string(),
                FeatureDesiredState::Enabled,
            )]),
            capabilities: BTreeMap::new(),
        };

        let actions = plan_reconciliation(&snapshot, &policy);
        assert!(actions.is_empty());
    }
}

