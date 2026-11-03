/*
 * File: mod.rs                                                                *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\system_features\mod.rs *
 * Project: system_features                                                    *
 * Author: pi-maaster77                                                        *
 * Created Date: Mo/10/2026 01:20:14                                           *
 * Last Modified: Thu Oct 22 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

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

use plan::{
    find_desired_state, find_state_case_insensitive, plan_changed_reconciliation,
    render_progress_bar,
};
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

    let mut completed_actions: Vec<FeatureAction> = Vec::new();
    let mut execution_error: Option<DismError> = None;

    for action in actions {
        match action {
            FeatureAction::EnableFeature(ref name) => {
                warn!(feature = %name, action = "enable", "La característica contradice la política de Nickel; se activa.");
            }
            FeatureAction::DisableFeature(ref name) => {
                warn!(feature = %name, action = "disable", "La característica contradice la política de Nickel; se desactiva.");
            }
            FeatureAction::AddCapability(ref name) => {
                warn!(capability = %name, action = "add", "La capacidad contradice la política de Nickel; se instala.");
            }
            FeatureAction::RemoveCapability(ref name) => {
                warn!(capability = %name, action = "remove", "La capacidad contradice la política de Nickel; se quita.");
            }
        }

        match execute_action(&session, &action) {
            Ok(reboot_required) => {
                completed_actions.push(action);
                if reboot_required {
                    warn!(
                        "La operación completada solicita reiniciar el equipo. Se pausan las operaciones restantes del lote para evitar acumulación de transacciones pendientes en Windows (CBS) que puedan congelar el arranque o el entorno gráfico."
                    );
                    break;
                }
            }
            Err(error) => {
                execution_error = Some(error);
                break;
            }
        }
    }

    if let Some(error) = execution_error {
        error!(
            error = %error,
            "Fallo durante la reconciliación. Iniciando rollback automático para restaurar el sistema..."
        );
        rollback_actions(&session, completed_actions);
        return Err(error)
            .context("falló la aplicación de características del sistema; se ejecutó rollback");
    }

    let updated = read_snapshot_from_session(&session)?;
    log_changes(&current, &updated, policy);
    Ok(updated)
}

fn execute_action(
    session: &DismSession,
    action: &FeatureAction,
) -> std::result::Result<bool, DismError> {
    let (item_type, name, action_label) = match action {
        FeatureAction::EnableFeature(name) => ("Característica opcional", name.as_str(), "enable"),
        FeatureAction::DisableFeature(name) => {
            ("Característica opcional", name.as_str(), "disable")
        }
        FeatureAction::AddCapability(name) => ("Capacidad de Windows", name.as_str(), "add"),
        FeatureAction::RemoveCapability(name) => ("Capacidad de Windows", name.as_str(), "remove"),
    };

    let mut last_percent: Option<u32> = None;
    let mut progress_cb = |current: u32, total: u32| {
        let percent = if total > 0 {
            (current.min(total) * 100) / total
        } else {
            0
        };

        let should_log = match last_percent {
            None => true,
            Some(last) => (percent >= last + 20) || (percent == 100 && last < 100),
        };

        if should_log {
            last_percent = Some(percent);
            let bar = render_progress_bar(percent);
            info!(
                item_type,
                name,
                action = action_label,
                progress = %bar,
                percent,
                "Descarga / operación en progreso."
            );
        }
    };

    let res = match action {
        FeatureAction::EnableFeature(name) => {
            session.enable_feature_with_progress(name, true, Some(&mut progress_cb))
        }
        FeatureAction::DisableFeature(name) => {
            session.disable_feature_with_progress(name, false, Some(&mut progress_cb))
        }
        FeatureAction::AddCapability(name) => {
            session.add_capability_with_progress(name, false, Some(&mut progress_cb))
        }
        FeatureAction::RemoveCapability(name) => {
            session.remove_capability_with_progress(name, Some(&mut progress_cb))
        }
    };

    match res {
        Ok(()) => {
            let bar = render_progress_bar(100);
            info!(
                item_type,
                name,
                action = action_label,
                progress = %bar,
                restart_required = false,
                "Descarga y aplicación completada exitosamente; DISM no solicita reinicio."
            );
            Ok(false)
        }
        Err(DismError::RebootRequired) => {
            let bar = render_progress_bar(100);
            info!(
                item_type,
                name,
                action = action_label,
                progress = %bar,
                restart_required = true,
                "Descarga y aplicación completada; requiere reiniciar el equipo."
            );
            Ok(true)
        }
        Err(error) => {
            error!(
                item_type,
                name,
                action = action_label,
                error = %error,
                "Fallo al ejecutar la operación."
            );
            Err(error)
        }
    }
}

fn rollback_actions(session: &DismSession, completed: Vec<FeatureAction>) {
    if completed.is_empty() {
        return;
    }

    warn!(
        completed_count = completed.len(),
        "Iniciando ROLLBACK automático de las características aplicadas en esta ejecución..."
    );

    for action in completed.into_iter().rev() {
        let inverse = action.inverse();
        warn!(
            original_action = ?action,
            rollback_action = ?inverse,
            "Aplicando rollback..."
        );
        match execute_action(session, &inverse) {
            Ok(_) => {
                info!(
                    rollback_action = ?inverse,
                    "Rollback de la acción completado exitosamente."
                );
            }
            Err(error) => {
                error!(
                    rollback_action = ?inverse,
                    error = %error,
                    "Fallo al ejecutar el rollback para esta acción; continuando con las restantes."
                );
            }
        }
    }

    info!("Proceso de ROLLBACK finalizado. El sistema fue restaurado al estado previo.");
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
