/*
 * File: mod.rs                                                                *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\certs\mod.rs *
 * Project: certs                                                              *
 * Author: pi-maaster77                                                        *
 * Created Date: We/10/2026 16:02:19                                           *
 * Last Modified: Fri Oct 16 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

//! Audits `LocalMachine\\Root` and applies the configured certificate policy.
//!
//! Imports are a separate, opt-in operation: they require both `allow_import`
//! and `allow_destructive`. `alert_only` disables policy-driven deletion but
//! does not disable an explicitly authorized import.


mod import;
mod store;

use crate::config::inspectors::{CertificateConfig, CertificatePolicy};
use crate::logger::{self, ComponentLoggerGuard};
use schannel::cert_store::CertStore;
use tracing::{error, info};
use std::thread;
use std::time::Duration;

/// Audits and enforces certificate policy for the Windows machine root store.
pub struct CertsInspector {
    component_name: String,
    policy: CertificatePolicy,
    allow_import: bool,
    import_certificates: Vec<std::path::PathBuf>,
    _logger_guard: ComponentLoggerGuard,
}

impl CertsInspector {
    /// Creates the inspector from validated Nickel configuration.
    pub fn new(component_name: &str, config: CertificateConfig) -> Self {
        let guard = logger::init_component_logger(component_name);
        if let Some(error) = config.load_error.as_deref() {
            error!(
                component = component_name,
                error = %error,
                "No se pudo cargar Nickel; se activa el modo de emergencia alert_only."
            );
        }
        info!(component = component_name, mode = ?config.policy.mode(), "Inspector de certificados inicializado.");

        Self {
            component_name: component_name.to_string(),
            policy: config.policy,
            allow_import: config.allow_import,
            import_certificates: config.import_certificates,
            _logger_guard: guard,
        }
    }

    /// Performs any explicitly authorized imports, then polls the store until stopped.
    pub fn execute(&self) -> anyhow::Result<()> {
        info!(
            component = %self.component_name,
            "Iniciando escaneo activo y purga de confianza..."
        );

        if self.allow_import {
            if let Err(error) = import::import_third_party_certificates(
                &self.component_name,
                &self.policy,
                &self.import_certificates,
            ) {
                error!(
                    component = %self.component_name,
                    error = %error,
                    "Falló la importación de certificados externos."
                );
            }
        }

        let mut previous_inventory = None;
        loop {
            match CertStore::open_local_machine("Root") {
                Ok(store) => {
                    store::inspect_store(
                        &self.component_name,
                        &self.policy,
                        &store,
                        &mut previous_inventory,
                    );
                }
                Err(e) => {
                    error!(
                        component = %self.component_name,
                        error = %e,
                        "Fallo al abrir el almacén raíz."
                    );
                }
            }

            thread::sleep(Duration::from_secs(2));
        }
    }
}