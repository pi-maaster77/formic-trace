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
use std::collections::HashMap;
use std::path::PathBuf;
use schannel::cert_context::CertContext;
use schannel::cert_store::CertAdd;
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

    /// Ejecuta el flujo completo de calibración, purga controlada y restauración
    pub fn run_calibration(&self) -> anyhow::Result<()> {
        info!(component = "InspectorsCalibrator", "Iniciando calibración del sistema (Modo Aprendizaje y Endurecimiento)...");

        let mut store = CertStore::open_local_machine("Root")?;

        // 1. Capturar la línea base inicial y respaldar los bytes DER de todos los certificados
        info!(component = "InspectorsCalibrator", "Inspeccionando almacén raíz (estado inicial) y respaldando...");
        let mut original_ders = Vec::new();
        let initial_certs = self.calibrate_store(&store, &mut original_ders)?;
        let original_hashes = self.hash_certificates(&initial_certs)?;

        // Keep the probe result so restoration still runs if inspecting the store fails.
        let mut deleted_ders = Vec::new();
        info!(component = "InspectorsCalibrator", "Intentando eliminar los certificados del almacén raíz...");
        let probe_result = (|| -> anyhow::Result<Vec<String>> {
            let mut deleted_count = 0;
            let mut delete_failed_count = 0;

            for cert in store.certs() {
                let der = cert.to_der().to_vec();
                match cert.delete() {
                    Ok(_) => {
                        deleted_count += 1;
                        deleted_ders.push(der);
                    }
                    Err(_) => delete_failed_count += 1,
                }
            }

            info!(
                component = "InspectorsCalibrator",
                deleted = deleted_count,
                delete_failed = delete_failed_count,
                "Resultados del intento de eliminación de certificados."
            );

            let surviving_store = CertStore::open_local_machine("Root")?;
            let surviving_certs = surviving_store.certs().collect::<Vec<_>>();
            self.hash_certificates(&surviving_certs)
        })();

        // Restore only certificates missing from the post-delete inventory, avoiding duplicates.
        info!(component = "InspectorsCalibrator", "Restaurando los certificados eliminados...");
        let restore_ders = match &probe_result {
            Ok(surviving_hashes) => {
                let mut remaining_counts = HashMap::new();
                for hash in surviving_hashes {
                    *remaining_counts.entry(hash.as_str()).or_insert(0usize) += 1;
                }
                original_ders
                    .iter()
                    .zip(&original_hashes)
                    .filter_map(|(der, hash)| {
                        let count = remaining_counts.entry(hash.as_str()).or_insert(0);
                        if *count > 0 {
                            *count -= 1;
                            None
                        } else {
                            Some(der)
                        }
                    })
                    .collect::<Vec<_>>()
            }
            Err(_) => deleted_ders.iter().collect::<Vec<_>>(),
        };
        let mut restoration_errors = Vec::new();
        for der in restore_ders {
            match CertContext::new(der) {
                Ok(cert) => {
                    if let Err(error) = store.add_cert(&cert, CertAdd::Always) {
                        restoration_errors.push(format!("add certificate: {error:?}"));
                    }
                }
                Err(error) => restoration_errors.push(format!("decode certificate: {error:?}")),
            }
        }
        let restoration_result = if restoration_errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "failed to restore {} certificate(s): {}",
                restoration_errors.len(),
                restoration_errors.join("; ")
            ))
        };

        let surviving_hashes = match (probe_result, restoration_result) {
            (Ok(hashes), Ok(())) => hashes,
            (Err(probe_error), Ok(())) => return Err(probe_error),
            (Ok(_), Err(restore_error)) => return Err(restore_error),
            (Err(probe_error), Err(restore_error)) => {
                return Err(anyhow::anyhow!(
                    "{probe_error}; restoration also failed: {restore_error}"
                ));
            }
        };

        info!(
            component = "InspectorsCalibrator",
            total_original = original_hashes.len(),
            total_surviving = surviving_hashes.len(),
            "Calibración de certificados completada y almacén restaurado."
        );

        // Persistir ambas listas en el archivo de configuración con el formato multilínea solicitado
        self.save_baselines(&original_hashes, &surviving_hashes)?;

        info!(component = "InspectorsCalibrator", "Calibración completada con éxito. Línea base guardada.");
        Ok(())
    }

    /// Extrae los certificados y respalda sus bytes DER
    fn calibrate_store(&self, store: &CertStore, ders_backup: &mut Vec<Vec<u8>>) -> anyhow::Result<Vec<CertContext>> {
        let mut certs = Vec::new();
        for cert in store.certs() {
            ders_backup.push(cert.to_der().to_vec());
            certs.push(cert);
        }
        Ok(certs)
    }

    /// Genera los hashes SHA-1 formateados en hexadecimal
    fn hash_certificates(&self, certs: &[CertContext]) -> anyhow::Result<Vec<String>> {
        let mut hashes = Vec::new();
        for cert in certs {
            let fingerprint_bytes = cert.fingerprint(schannel::cert_context::HashAlgorithm::sha1())?;
            let hash_hex = fingerprint_bytes.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            hashes.push(hash_hex);
        }
        Ok(hashes)
    }

    /// Guarda la línea base aplicando el formato estético de lista con comas y saltos de línea
    fn save_baselines(&self, original_hashes: &[String], surviving_hashes: &[String]) -> anyhow::Result<()> {
        if let Some(parent) = self.baseline_output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let original_joined = original_hashes
            .iter()
            .map(|h| format!("    \"{}\"", h))
            .collect::<Vec<String>>()
            .join(",\n");

        let surviving_joined = surviving_hashes
            .iter()
            .map(|h| format!("    \"{}\"", h))
            .collect::<Vec<String>>()
            .join(",\n");

        let content = format!(
            "# Generado automáticamente por Formic Calibrator\n\
             allowed_root_thumbprints = [\n{}\n]\n\n\
             mandatory_kernel_thumbprints = [\n{}\n]\n",
            original_joined,
            surviving_joined
        );

        fs::write(&self.baseline_output_path, content)?;
        info!(component = "InspectorsCalibrator", path = ?self.baseline_output_path, "Archivo de línea base persistido con formato multilínea.");
        Ok(())
    }
}