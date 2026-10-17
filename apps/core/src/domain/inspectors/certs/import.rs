use crate::config::inspectors::CertificatePolicy;
use schannel::cert_context::{CertContext, HashAlgorithm};
use schannel::cert_store::{CertAdd, CertStore};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;

pub(super) fn import_third_party_certificates(
    component_name: &str,
    policy: &CertificatePolicy,
    import_certificates: &[PathBuf],
) -> anyhow::Result<()> {
    if import_certificates.is_empty() {
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

    for path in import_certificates {
        let certificate = load_certificate_file(path)?;
        let thumbprint = encode_hex(&certificate.fingerprint(HashAlgorithm::sha256())?);
        let (_, parsed) = parse_x509_certificate(certificate.to_der())
            .map_err(|error| anyhow::anyhow!("DER X.509 inválido en {}: {error}", path.display()))?;
        let is_self_signed_leaf = validate_import_candidate(&certificate, &parsed)?;
        if is_self_signed_leaf {
            warn!(
                component = component_name,
                path = %path.display(),
                thumbprint = %thumbprint,
                "Se autoriza explícitamente un certificado autofirmado sin CA:true como ancla de confianza."
            );
        }

        let issuer_hash = issuer_name_sha256(&certificate)?;
        if policy.should_delete(&thumbprint, Some(&issuer_hash)) {
            warn!(
                component = component_name,
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
            component = component_name,
            path = %path.display(),
            thumbprint = %thumbprint,
            "Certificado CA externo importado en LocalMachine\\Root."
        );
    }

    info!(
        component = component_name,
        imported = imported_count,
        skipped = skipped_count,
        "Carga de certificados externos completada."
    );
    Ok(())
}

fn validate_import_candidate(
    certificate: &CertContext,
    parsed: &X509Certificate<'_>,
) -> anyhow::Result<bool> {
    if !certificate.is_time_valid()? {
        anyhow::bail!("el certificado está fuera de su período de validez");
    }

    if parsed.is_ca() {
        return Ok(false);
    }

    if parsed.subject() != parsed.issuer() {
        anyhow::bail!("el certificado no es CA ni está autofirmado");
    }

    parsed
        .verify_signature(None)
        .map_err(|error| anyhow::anyhow!("falló la verificación de autofirma: {error}"))?;
    Ok(true)
}

pub(super) fn issuer_name_sha256(certificate: &CertContext) -> anyhow::Result<String> {
    let (_, parsed) = parse_x509_certificate(certificate.to_der())
        .map_err(|error| anyhow::anyhow!("DER X.509 inválido: {error}"))?;
    let digest = Sha256::digest(parsed.issuer().as_raw());
    Ok(encode_hex(&digest))
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn load_certificate_file(path: &Path) -> anyhow::Result<CertContext> {
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

#[cfg(test)]
mod tests {
    use super::encode_hex;

    #[test]
    fn hex_encoding_is_lowercase_and_padded() {
        assert_eq!(encode_hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}