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
use tracing::info;
use schannel::cert_store::CertStore;

pub struct InspectorsCalibrator {
    baseline_output_path: PathBuf,
}

impl InspectorsCalibrator {
    pub fn new(output_path: PathBuf) -> Self {
        Self {
            baseline_output_path: output_path,
        }
    }

    /// Ejecuta el flujo de calibración de la línea base del sistema
    pub fn run_calibration(&self) -> anyhow::Result<()> {
        info!("Iniciando calibración del sistema (Modo Aprendizaje)...");

        // 1. Calibración del subsistema de certificados raíz
        let cert_hashes = self.calibrate_certificates()?;
        
        // 2. Persistir la línea base en un formato estructurado o archivo de configuración
        self.save_baseline(&cert_hashes)?;

        info!("Calibración completada con éxito. Línea base guardada.");
        Ok(())
    }

fn calibrate_certificates(&self) -> anyhow::Result<Vec<String>> {
        info!("Inspeccionando almacén raíz para extraer línea base de confianza...");
        let store = CertStore::open_local_machine("Root")?;
        let mut hashes = Vec::new();

        for cert in store.certs() {
            if let Ok(fingerprint_bytes) = cert.fingerprint(schannel::cert_context::HashAlgorithm::sha1()) {
                let hash_hex = fingerprint_bytes.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                hashes.push(hash_hex);
            }
        }

        info!(total_certs_captured = hashes.len(), "Certificados base capturados.");
        Ok(hashes)
    }

    fn save_baseline(&self, cert_hashes: &[String]) -> anyhow::Result<()> {
        if let Some(parent) = self.baseline_output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = format!(
            "# Generado automáticamente por Formic Calibrator\nallowed_root_thumbprints = {:?}\n",
            cert_hashes
        );

        fs::write(&self.baseline_output_path, content)?;
        info!(path = ?self.baseline_output_path, "Archivo de línea base persistido.");
        Ok(())
    }
}