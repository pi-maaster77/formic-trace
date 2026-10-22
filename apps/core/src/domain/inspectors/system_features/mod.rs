/*
 * File: system_features.rs
 * Path: apps/core/src/domain/inspectors/system_features.rs
 * Project: inspectors
 * License: GNU General Public License v3.0 (GPLv3)
 */

//! Monitors Windows optional features and capabilities against Nickel policy.

mod dump;
mod plan;
mod snapshot;

pub use dump::dump_features;
pub use plan::{plan_reconciliation, FeatureAction};
pub use snapshot::SystemFeaturesSnapshot;

use anyhow::{Context, Result};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};
use windows_features::{Capability, DismError, DismSession, Feature};

use crate::config::inspectors::{FeatureDesiredState, SystemFeaturesPolicy};

use plan::{find_desired_state, find_state_case_insensitive, plan_changed_reconciliation};
use snapshot::log_snapshot;

const POLL_INTERVAL: Duration = Duration::from_secs(10);

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
    previous: &windows_features::FeatureState,
    current: &windows_features::FeatureState,
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
