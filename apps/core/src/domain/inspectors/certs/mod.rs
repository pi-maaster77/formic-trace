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


/*

Este archivo implementa el inspector activo de certificados de Formic operando en un modo de "Cero-Confianza Absoluto" (Zero-Trust). Su propósito principal es actuar como un centinela o guardia de seguridad en tiempo de ejecución:

    Sondeo Continuo (Polling): Ejecuta un bucle infinito que abre el almacén raíz local (LocalMachine\Root) cada 2 segundos para verificar si el estado del sistema ha sido alterado.

    Vigilancia de Integridad: Monitorea la cantidad de certificados en el almacén mediante store.certs().count().

    Respuesta Inmediata (Kill-Switch / Purga Activa): Si detecta que count > 0 (es decir, si cualquier aplicación, usuario o malware intenta inyectar o restaurar certificados raíz no autorizados), invoca inmediatamente la función purge_certificates() para borrarlos de golpe utilizando un comando lanzado por debajo (vía PowerShell).*/

use crate::logger::{self, ComponentLoggerGuard};
use tracing::{error, info, warn};
use schannel::cert_store::CertStore;
use std::thread;
use std::time::Duration;

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
                    self.purge_certificates(&store);
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

    fn purge_certificates(&self, store: &CertStore) {
        let certificates = store.certs().collect::<Vec<_>>();
        if certificates.is_empty() {
            return;
        }

        let mut deleted_count = 0;
        let mut delete_failed_count = 0;

        for certificate in certificates {
            match certificate.delete() {
                Ok(_) => deleted_count += 1,
                Err(error) => {
                    delete_failed_count += 1;
                    warn!(
                        component = %self.component_name,
                        error = %error,
                        "No se pudo eliminar un certificado raíz."
                    );
                }
            }
        }

        info!(
            component = %self.component_name,
            deleted = deleted_count,
            delete_failed = delete_failed_count,
            "Intento de purga de certificados raíz completado."
        );
    }
}