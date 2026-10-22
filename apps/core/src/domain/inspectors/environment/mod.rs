/*
 * File: mod.rs                                                                *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\environment\mod.rs *
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

mod diff;
mod plan;
mod registry;

use crate::config::inspectors::EnvironmentPolicy;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use tracing::{error, info};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::RegKey;

use diff::log_snapshot;
use registry::{reconcile_and_read, POLL_INTERVAL, SYSTEM_ENVIRONMENT_KEY, USER_ENVIRONMENT_KEY};

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

fn refresh_scope(
    scope: &str,
    root: &RegKey,
    subkey: &str,
    allowed: &BTreeMap<String, String>,
    previous: &mut BTreeMap<String, String>,
) {
    match reconcile_and_read(scope, root, subkey, allowed) {
        Ok(current) => {
            diff::log_changes(scope, previous, &current);
            *previous = current;
        }
        Err(error) => {
            error!(scope, error = %error, "Falló la reconciliación de variables de entorno.")
        }
    }
}
