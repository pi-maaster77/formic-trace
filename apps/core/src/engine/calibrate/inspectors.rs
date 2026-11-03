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

use std::fs;
use std::path::PathBuf;
use schannel::cert_context::CertContext;
use tracing::info;
use schannel::cert_store::CertStore;

use crate::logger;

pub struct InspectorsCalibrator {
    baseline_output_path: PathBuf,
    _logger_guard: logger::ComponentLoggerGuard,
}

impl InspectorsCalibrator {
    pub fn new(output_path: PathBuf) -> Self {
        let guard = logger::init_component_logger("InspectorsCalibrator");
        info!(component = "InspectorsCalibrator", "Subsistema de calibración de inspectores.");
        Self {
            baseline_output_path: output_path,
            _logger_guard: guard,
        }
    }

    /// Captura una línea base de solo lectura del almacén raíz.
    pub fn run_calibration(&self) -> anyhow::Result<()> {
        info!(component = "InspectorsCalibrator", "Capturando línea base sin modificar el almacén raíz...");

        let store = CertStore::open_local_machine("Root")?;
        let certificates = store.certs().collect::<Vec<_>>();
        let hashes = self.hash_certificates(&certificates)?;
        self.save_baseline(&hashes)?;

        info!(
            component = "InspectorsCalibrator",
            total = hashes.len(),
            "Línea base SHA-256 guardada."
        );
        Ok(())
    }

    /// Genera las huellas SHA-256 formateadas en hexadecimal.
    fn hash_certificates(&self, certs: &[CertContext]) -> anyhow::Result<Vec<String>> {
        let mut hashes = Vec::new();
        for cert in certs {
            let fingerprint_bytes = cert.fingerprint(schannel::cert_context::HashAlgorithm::sha256())?;
            let hash_hex = fingerprint_bytes.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            hashes.push(hash_hex);
        }
        Ok(hashes)
    }

    /// Guarda el inventario observado como línea base Nickel-compatible vía TOML.
    fn save_baseline(&self, hashes: &[String]) -> anyhow::Result<()> {
        if let Some(parent) = self.baseline_output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let joined = hashes
            .iter()
            .map(|h| format!("    \"{}\"", h))
            .collect::<Vec<String>>()
            .join(",\n");

        let content = format!(
            "# Inventario observado por Formic Calibrator; revisar antes de habilitar borrados.\n\
             baseline_sha256 = [\n{}\n]\n",
            joined
        );

        fs::write(&self.baseline_output_path, content)?;
        info!(component = "InspectorsCalibrator", path = ?self.baseline_output_path, "Archivo de línea base persistido.");
        Ok(())
    }
}