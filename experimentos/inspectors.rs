/*
 * File: inspectors.rs                                                         *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\engine\calibrate\inspectors.rs *
 * Project: calibrate                                                          *
 * Author: pi-maaster77                                                        *
 * Created Date: Th/10/2026 02:31:34                                           *
 * Last Modified: Thu Oct 15 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */


/* 
este archivo, originalmente era para calibrar los inspectores, pero ahora se ha convertido en un módulo de prueba para eliminar certificados raíz y mostrar el inventario cada 500 ms.
es interesante porque deja limpito el almacén de certificados raíz y permite ver en tiempo real cómo se comporta el sistema ante la ausencia de certificados confiables.

*/
use std::io::{self, Write};
use std::thread;
use std::time::Duration;
use tracing::info;
use schannel::cert_store::CertStore;

use crate::logger;

pub struct InspectorsCalibrator {
    _logger_guard: logger::ComponentLoggerGuard,
}

impl InspectorsCalibrator {
    pub fn new() -> Self {
        let guard = logger::init_component_logger("InspectorsCalibrator");
        info!(component = "InspectorsCalibrator", "Subsistema de calibración de inspectores.");
        Self {
            _logger_guard: guard,
        }
    }

    /// Elimina los certificados raíz y muestra el inventario cada 500 ms.
    pub fn run_calibration(&self) -> anyhow::Result<()> {
        println!("ADVERTENCIA: se eliminarán certificados de LocalMachine\\Root y no se restaurarán.");
        print!("Escribe BORRAR para continuar: ");
        io::stdout().flush()?;

        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        if confirmation.trim() != "BORRAR" {
            println!("Operación cancelada.");
            return Ok(());
        }

        info!(component = "InspectorsCalibrator", "Iniciando eliminación de certificados del almacén raíz...");
        let store = CertStore::open_local_machine("Root")?;
        let certificates = store.certs().collect::<Vec<_>>();
        let mut deleted_count = 0;
        let mut delete_failed_count = 0;

        for cert in certificates {
            match cert.delete() {
                Ok(_) => deleted_count += 1,
                Err(_) => delete_failed_count += 1,
            }
        }

        info!(
            component = "InspectorsCalibrator",
            deleted = deleted_count,
            delete_failed = delete_failed_count,
            "Intento de eliminación completado."
        );

        loop {
            match CertStore::open_local_machine("Root") {
                Ok(store) => {
                    let count = store.certs().count();
                    println!("Certificados en LocalMachine\\Root: {count}");
                }
                Err(error) => {
                    eprintln!("No se pudo consultar LocalMachine\\Root: {error}");
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
}