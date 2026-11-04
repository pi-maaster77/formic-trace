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

mod debug_reports;
mod dump;
mod plan;
mod snapshot;

pub use dump::dump_features;
pub use plan::{plan_reconciliation, FeatureAction};
pub use snapshot::SystemFeaturesSnapshot;

use anyhow::{Context, Result};
use std::collections::HashSet;
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
    find_desired_capability_state, find_desired_state, find_state_case_insensitive,
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
    let mut restart_required = false;
    let mut awaiting_snapshot = false;
    let mut failed_actions = HashSet::new();
    let mut snapshot = match reconcile_and_read(
        policy,
        None,
        true,
        &mut restart_required,
        &mut awaiting_snapshot,
        &mut failed_actions,
    ) {
        Ok(snapshot) => Some(snapshot),
        Err(error) => {
            warn!(error = %error, "No se pudo realizar el snapshot inicial de características (¿se requieren permisos de administrador?).");
            if let Err(report_error) =
                debug_reports::write_unavailable_reports(policy, &format!("{error:#}"))
            {
                error!(error = %report_error, "No se pudieron escribir los informes de depuración de características.");
            }
            None
        }
    };

    if let Some(snapshot) = &snapshot {
        log_snapshot(snapshot);
    }
    info!(
        poll_interval_seconds = POLL_INTERVAL.as_secs(),
        "Monitoreo de características opcionales y capacidades activo; Ctrl+C para detener."
    );

    while running.load(Ordering::Relaxed) {
        thread::park_timeout(POLL_INTERVAL);
        if !running.load(Ordering::Relaxed) {
            break;
        }
        let apply_policy = !restart_required && !awaiting_snapshot;
        match reconcile_and_read(
            policy,
            snapshot.as_ref(),
            apply_policy,
            &mut restart_required,
            &mut awaiting_snapshot,
            &mut failed_actions,
        ) {
            Ok(current) => {
                if awaiting_snapshot && !restart_required {
                    awaiting_snapshot = false;
                }
                if snapshot.is_none() {
                    log_snapshot(&current);
                }
                snapshot = Some(current);
            }
            Err(error) if snapshot.is_none() => {
                warn!(error = %error, "No se pudo capturar el snapshot inicial; se volverá a intentar.");
                if let Err(report_error) =
                    debug_reports::write_unavailable_reports(policy, &format!("{error:#}"))
                {
                    error!(error = %report_error, "No se pudieron escribir los informes de depuración de características.");
                }
            }
            Err(error) => {
                error!(error = %error, "Falló la reconciliación de características del sistema.");
                if let Err(report_error) =
                    debug_reports::write_unavailable_reports(policy, &format!("{error:#}"))
                {
                    error!(error = %report_error, "No se pudieron escribir los informes de depuración de características.");
                }
            }
        }
    }

    info!("Monitoreo de características del sistema detenido.");
    Ok(())
}

fn reconcile_and_read(
    policy: &SystemFeaturesPolicy,
    previous: Option<&SystemFeaturesSnapshot>,
    apply_policy: bool,
    restart_required: &mut bool,
    awaiting_snapshot: &mut bool,
    failed_actions: &mut HashSet<FeatureAction>,
) -> Result<SystemFeaturesSnapshot> {
    let session = match DismSession::open_online() {
        Ok(session) => session,
        Err(DismError::ElevationRequired) => {
            return Err(DismError::ElevationRequired)
                .context("se requieren permisos de Administrador para abrir DISM");
        }
        Err(error) => return Err(error).context("falló al abrir la sesión online de DISM"),
    };

    let current = read_snapshot_from_session(&session)?;
    if let Some(previous) = previous {
        log_changes(previous, &current, policy);
    }
    let actions = plan_reconciliation(&current, policy);
    failed_actions.retain(|failed| actions.contains(failed));
    let suppressed_actions: Vec<_> = actions
        .iter()
        .filter(|action| failed_actions.contains(*action))
        .cloned()
        .collect();
    let pause_note = if *restart_required {
        "DISM pidió reiniciar; no se enviarán más operaciones hasta reiniciar el equipo."
    } else if *awaiting_snapshot {
        "Las operaciones quedan pausadas hasta obtener un inventario confiable."
    } else if !apply_policy {
        "Inventario de solo lectura."
    } else {
        "Se aplica la política a todas las diferencias detectadas."
    };
    if let Err(error) = debug_reports::write_before_reconciliation(
        &current,
        policy,
        &actions,
        &suppressed_actions,
        pause_note,
    ) {
        error!(error = %error, "No se pudieron escribir los informes de depuración previos a la reconciliación.");
    }

    if !apply_policy {
        if let Err(error) = debug_reports::write_final_report(&current, pause_note) {
            error!(error = %error, "No se pudo escribir el informe final de características.");
        }
        return Ok(current);
    }

    let mut action_attempted = false;

    let runnable_actions: Vec<_> = actions
        .into_iter()
        .filter(|action| !failed_actions.contains(action))
        .collect();
    for action in runnable_actions {
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

        action_attempted = true;
        match execute_action(&session, &action) {
            Ok(reboot_required) => {
                *awaiting_snapshot = true;
                if reboot_required {
                    *restart_required = true;
                    warn!(
                        "La operación completada solicita reiniciar el equipo. Se pausan las operaciones restantes del lote para evitar acumulación de transacciones pendientes en Windows (CBS) que puedan congelar el arranque o el entorno gráfico."
                    );
                    break;
                }
            }
            Err(error) => {
                failed_actions.insert(action.clone());
                error!(
                    error = %error,
                    action = ?action,
                    "La acción falló; no se revertirán las operaciones anteriores. Se continuará con las demás diferencias."
                );
            }
        }
    }

    if !action_attempted {
        if let Err(error) =
            debug_reports::write_final_report(&current, "No había operaciones pendientes.")
        {
            error!(error = %error, "No se pudo escribir el informe final de características.");
        }
        return Ok(current);
    }

    let updated = match read_snapshot_from_session(&session) {
        Ok(updated) => updated,
        Err(error) => {
            if let Err(report_error) = debug_reports::write_final_report(
                &current,
                &format!(
                    "No se pudo verificar el resultado posterior a las operaciones: {error:#}"
                ),
            ) {
                error!(error = %report_error, "No se pudo escribir el informe final de características.");
            }
            return Err(error)
                .context("no se pudo verificar el inventario después de aplicar la política");
        }
    };
    log_changes(&current, &updated, policy);
    *awaiting_snapshot = false;
    if let Err(error) = debug_reports::write_final_report(
        &updated,
        "Inventario consultado después del lote de operaciones.",
    ) {
        error!(error = %error, "No se pudo escribir el informe final de características.");
    }
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
                find_desired_capability_state(&policy.capabilities, name),
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
    if previous.is_transition_pending() || current.is_transition_pending() {
        info!(
            item_type = kind,
            name,
            previous_state = ?previous,
            new_state = ?current,
            desired_state = ?desired,
            "Cambió el estado DISM; hay una transacción de instalación o eliminación pendiente."
        );
        return;
    }
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
