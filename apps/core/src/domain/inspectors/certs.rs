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

/* este modulo es responsable de gestionar la inspección y purga de certificados raíz */


use crate::logger::{self, ComponentLoggerGuard};
use crate::config::inspectors::{CertificateConfig, CertificateMode, CertificatePolicy};
use schannel::cert_context::{CertContext, HashAlgorithm};
use schannel::cert_store::CertAdd;
use tracing::{error, info, warn};
use schannel::cert_store::CertStore;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::fmt::Write as _;
use std::thread;
use std::time::Duration;
use x509_parser::parse_x509_certificate;

pub struct CertsInspector {
    component_name: String,
    policy: CertificatePolicy,
    allow_import: bool,
    import_certificates: Vec<std::path::PathBuf>,
    _logger_guard: ComponentLoggerGuard,
}

impl CertsInspector {
    pub fn new(component_name: &str, config: CertificateConfig) -> Self {
        let guard = logger::init_component_logger(component_name);
        info!(component = component_name, mode = ?config.policy.mode(), "Inspector de certificados inicializado.");

        Self {
            component_name: component_name.to_string(),
            policy: config.policy,
            allow_import: config.allow_import,
            import_certificates: config.import_certificates,
            _logger_guard: guard,
        }
    }

    pub fn execute(&self) -> anyhow::Result<()> {
        info!(
            component = %self.component_name,
            "Iniciando escaneo activo y purga de confianza..."
        );

        if self.allow_import && self.policy.mode() != CertificateMode::AlertOnly {
            if let Err(error) = self.import_third_party_certificates() {
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
                    self.inspect_store(&store, &mut previous_inventory);
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

    fn import_third_party_certificates(&self) -> anyhow::Result<()> {
        if self.import_certificates.is_empty() {
            return Ok(());
        }

        let mut store = CertStore::open_local_machine("Root")?;
        let mut existing = store
            .certs()
            .filter_map(|certificate| {
                certificate
                    .fingerprint(HashAlgorithm::sha256())
                    .ok()
                    .map(|fingerprint| encode_hex(&fingerprint))
            })
            .collect::<HashSet<_>>();
        let mut imported_count = 0;
        let mut skipped_count = 0;

        for path in &self.import_certificates {
            let certificate = load_certificate_file(path)?;
            let thumbprint = encode_hex(&certificate.fingerprint(HashAlgorithm::sha256())?);
            let (_, parsed) = parse_x509_certificate(certificate.to_der())
                .map_err(|error| anyhow::anyhow!("DER X.509 inválido en {}: {error}", path.display()))?;
            if !parsed.is_ca() || !certificate.is_time_valid()? {
                anyhow::bail!(
                    "el certificado debe ser una CA actualmente válida: {}",
                    path.display()
                );
            }

            let issuer_hash = issuer_name_sha256(&certificate)?;
            if self.policy.should_delete(&thumbprint, Some(&issuer_hash)) {
                warn!(
                    component = %self.component_name,
                    path = %path.display(),
                    thumbprint = %thumbprint,
                    "Certificado externo omitido porque la política lo eliminaría."
                );
                skipped_count += 1;
                continue;
            }

            if existing.contains(&thumbprint) {
                skipped_count += 1;
                continue;
            }

            store.add_cert(&certificate, CertAdd::Always)?;
            existing.insert(thumbprint.clone());
            imported_count += 1;
            info!(
                component = %self.component_name,
                path = %path.display(),
                thumbprint = %thumbprint,
                "Certificado CA externo importado en LocalMachine\\Root."
            );
        }

        info!(
            component = %self.component_name,
            imported = imported_count,
            skipped = skipped_count,
            "Carga de certificados externos completada."
        );
        Ok(())
    }

    fn inspect_store(
        &self,
        store: &CertStore,
        previous_inventory: &mut Option<HashSet<String>>,
    ) {
        let certificates = store.certs().collect::<Vec<_>>();
        let initial_scan = previous_inventory.is_none();
        let previous = previous_inventory.as_ref();
        let mut current_inventory = HashSet::new();
        let mut deleted_count = 0;
        let mut delete_failed_count = 0;
        let mut new_count = 0;

        for certificate in certificates {
            let thumbprint = match certificate.fingerprint(HashAlgorithm::sha256()) {
                Ok(fingerprint) => encode_hex(&fingerprint),
                Err(error) => {
                    warn!(
                        component = %self.component_name,
                        error = %error,
                        "No se pudo calcular la huella SHA-256; se conserva el certificado."
                    );
                    continue;
                }
            };
            current_inventory.insert(thumbprint.clone());

            let added_since_start = if initial_scan {
                self.policy.mode() == crate::config::inspectors::CertificateMode::AlertOnly
                    && self.policy.has_baseline()
                    && !self.policy.baseline_contains(&thumbprint)
            } else {
                previous.is_some_and(|inventory| !inventory.contains(&thumbprint))
            };

            if added_since_start {
                new_count += 1;
                warn!(
                    component = %self.component_name,
                    thumbprint = %thumbprint,
                    "Se detectó un certificado raíz nuevo."
                );
            }

            let issuer_hash = match issuer_name_sha256(&certificate) {
                Ok(hash) => Some(hash),
                Err(error) => {
                    warn!(
                        component = %self.component_name,
                        thumbprint = %thumbprint,
                        error = %error,
                        "No se pudo leer el issuer X.509."
                    );
                    None
                }
            };

            if !self.policy.should_delete(&thumbprint, issuer_hash.as_deref()) {
                continue;
            }

            match certificate.delete() {
                Ok(()) => deleted_count += 1,
                Err(error) => {
                    delete_failed_count += 1;
                    warn!(
                        component = %self.component_name,
                        thumbprint = %thumbprint,
                        error = %error,
                        "No se pudo eliminar el certificado raíz seleccionado."
                    );
                }
            }
        }

        if initial_scan || deleted_count > 0 || delete_failed_count > 0 || new_count > 0 {
            info!(
                component = %self.component_name,
                mode = ?self.policy.mode(),
                inventory = current_inventory.len(),
                new = new_count,
                deleted = deleted_count,
                delete_failed = delete_failed_count,
                "Inspección del almacén raíz completada."
            );
        }

        *previous_inventory = Some(current_inventory);
    }
}

fn issuer_name_sha256(certificate: &CertContext) -> anyhow::Result<String> {
    let (_, parsed) = parse_x509_certificate(certificate.to_der())
        .map_err(|error| anyhow::anyhow!("DER X.509 inválido: {error}"))?;
    let digest = Sha256::digest(parsed.issuer().as_raw());
    Ok(encode_hex(&digest))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::encode_hex;

    #[test]
    fn hex_encoding_is_lowercase_and_padded() {
        assert_eq!(encode_hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}

fn load_certificate_file(path: &std::path::Path) -> anyhow::Result<CertContext> {
    let contents = fs::read(path)?;
    let is_pem = std::str::from_utf8(&contents)
        .ok()
        .is_some_and(|text| text.trim_start().starts_with("-----BEGIN CERTIFICATE-----"));

    if is_pem {
        let text = std::str::from_utf8(&contents)?;
        if text.matches("-----BEGIN CERTIFICATE-----").count() != 1 {
            anyhow::bail!("cada archivo PEM debe contener exactamente un certificado");
        }
        Ok(CertContext::from_pem(text)?)
    } else {
        Ok(CertContext::new(&contents)?)
    }
}