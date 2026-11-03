use super::import::{encode_hex, issuer_name_sha256};
use crate::config::inspectors::{CertificateMode, CertificatePolicy};
use schannel::cert_context::HashAlgorithm;
use schannel::cert_store::CertStore;
use std::collections::HashSet;
use tracing::{error, info, warn};

pub(super) fn inspect_store(
    component_name: &str,
    policy: &CertificatePolicy,
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
                error!(
                    component = component_name,
                    error = %error,
                    "No se pudo calcular la huella SHA-256; se conserva el certificado."
                );
                continue;
            }
        };
        current_inventory.insert(thumbprint.clone());

        let added_since_start = if initial_scan {
            policy.mode() == CertificateMode::AlertOnly
                && policy.has_baseline()
                && !policy.baseline_contains(&thumbprint)
        } else {
            previous.is_some_and(|inventory| !inventory.contains(&thumbprint))
        };

        if added_since_start {
            new_count += 1;
            warn!(
                component = component_name,
                thumbprint = %thumbprint,
                "Se detectó un certificado raíz nuevo."
            );
        }

        let issuer_hash = match issuer_name_sha256(&certificate) {
            Ok(hash) => Some(hash),
            Err(error) => {
                error!(
                    component = component_name,
                    thumbprint = %thumbprint,
                    error = %error,
                    "No se pudo leer el issuer X.509."
                );
                None
            }
        };

        if !policy.should_delete(&thumbprint, issuer_hash.as_deref()) {
            continue;
        }

        match certificate.delete() {
            Ok(()) => deleted_count += 1,
            Err(error) => {
                delete_failed_count += 1;
                error!(
                    component = component_name,
                    thumbprint = %thumbprint,
                    error = %error,
                    "No se pudo eliminar el certificado raíz seleccionado."
                );
            }
        }
    }

    if initial_scan || deleted_count > 0 || delete_failed_count > 0 || new_count > 0 {
        info!(
            component = component_name,
            mode = ?policy.mode(),
            inventory = current_inventory.len(),
            new = new_count,
            deleted = deleted_count,
            delete_failed = delete_failed_count,
            "Inspección del almacén raíz completada."
        );
    }

    *previous_inventory = Some(current_inventory);
}