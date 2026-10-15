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
use tracing::{info, warn};
use schannel::cert_store::CertStore;
use std::thread;
use std::time::Duration;
use std::collections::HashSet;

pub struct CertsInspector {
    component_name: String,
    _logger_guard: ComponentLoggerGuard,
}

impl CertsInspector {
    pub fn new(component_name: &str) -> Self {
        let guard = logger::init_component_logger(component_name);
        info!(component = component_name, "Subsistema de certificados inicializado (Safe-Rust mode).");

        Self {
            component_name: component_name.to_string(),
            _logger_guard: guard,
        }
    }

    /// Monitoreo continuo en tiempo real utilizando la API segura de schannel y DER bytes
    pub fn execute(&self) -> anyhow::Result<()> {
        info!(
            component = %self.component_name,
            "Iniciando bucle de vigilancia declarativa para almacenes de certificados..."
        );

        let mut known_certs: HashSet<Vec<u8>> = HashSet::new();

        loop {
            match CertStore::open_local_machine("Root") {
                Ok(store) => {
                    let current_certs: HashSet<Vec<u8>> = store
                        .certs()
                        .map(|cert| cert.to_der().to_vec())
                        .collect();

                    if known_certs.is_empty() {
                        info!(
                            component = %self.component_name,
                            count = current_certs.len(),
                            "Línea base de certificados raíz establecida correctamente."
                        );
                        known_certs = current_certs;
                    } else {
                        // Detectar certificados agregados
                        for cert_der in &current_certs {
                            if !known_certs.contains(cert_der) {
                                warn!(
                                    component = %self.component_name,
                                    "¡Alerta Default-Deny! Se detectó un nuevo certificado raíz inyectado en el sistema."
                                );
                            }
                        }

                        // Detectar certificados eliminados
                        for cert_der in &known_certs {
                            if !current_certs.contains(cert_der) {
                                info!(
                                    component = %self.component_name,
                                    "Un certificado raíz fue removido del almacén del sistema."
                                );
                            }
                        }

                        known_certs = current_certs;
                    }
                }
                Err(e) => {
                    warn!(
                        component = %self.component_name,
                        error = %e,
                        "No se pudo acceder temporalmente al almacén de certificados de Windows."
                    );
                }
            }

            // Sondeo eficiente sin bloquear la CPU y respetando la política Safe-Rust
            thread::sleep(Duration::from_secs(5));
        }
    }
}