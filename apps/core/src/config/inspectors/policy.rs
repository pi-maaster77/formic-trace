use serde::Deserialize;
use std::collections::HashSet;
use std::path::PathBuf;

/// Selects how the certificate inspector evaluates and removes stored roots.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateMode {
	Minimal,
	PurgeAll,
	Whitelist,
	Blacklist,
	AlertOnly,
}

/// Validated runtime policy for the Windows machine root store.
#[derive(Debug, Clone)]
pub struct CertificatePolicy {
	pub(super) mode: CertificateMode,
	pub(super) baseline_sha256: HashSet<String>,
	pub(super) allow_sha256: HashSet<String>,
	pub(super) allow_issuer_name_sha256: HashSet<String>,
	pub(super) deny_sha256: HashSet<String>,
	pub(super) deny_issuer_name_sha256: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct CertificateConfig {
	/// Deletion and audit policy for existing certificates.
	pub policy: CertificatePolicy,
	/// Explicit permission to add listed certificates to the machine root store.
	pub allow_import: bool,
	/// Canonical files resolved below `inspectors/certs/third_party`.
	pub import_certificates: Vec<PathBuf>,
	/// Configuration failure retained until tracing has been initialized.
	pub load_error: Option<String>,
}

impl CertificatePolicy {
	pub fn emergency() -> Self {
		Self {
			mode: CertificateMode::AlertOnly,
			baseline_sha256: HashSet::new(),
			allow_sha256: HashSet::new(),
			allow_issuer_name_sha256: HashSet::new(),
			deny_sha256: HashSet::new(),
			deny_issuer_name_sha256: HashSet::new(),
		}
	}

	pub fn mode(&self) -> CertificateMode {
		self.mode
	}

	pub fn has_baseline(&self) -> bool {
		!self.baseline_sha256.is_empty()
	}

	pub fn baseline_contains(&self, thumbprint: &str) -> bool {
		self.baseline_sha256.contains(thumbprint)
	}

	pub fn should_delete(&self, thumbprint: &str, issuer_name_sha256: Option<&str>) -> bool {
		if self.mode == CertificateMode::AlertOnly {
			return false;
		}

		if self.mode == CertificateMode::PurgeAll {
			return true;
		}

		let issuer_is_denied = issuer_name_sha256
			.is_some_and(|hash| self.deny_issuer_name_sha256.contains(hash));
		if self.deny_sha256.contains(thumbprint) || issuer_is_denied {
			return true;
		}

		match self.mode {
			CertificateMode::Minimal => !self.baseline_sha256.contains(thumbprint),
			CertificateMode::Whitelist => {
				let certificate_is_allowed = self.allow_sha256.contains(thumbprint);
				let issuer_is_allowed = issuer_name_sha256
					.is_some_and(|hash| self.allow_issuer_name_sha256.contains(hash));
				!(certificate_is_allowed || issuer_is_allowed)
			}
			CertificateMode::Blacklist | CertificateMode::AlertOnly | CertificateMode::PurgeAll => {
				false
			}
		}
	}
}

impl CertificateConfig {
	fn emergency() -> Self {
		Self {
			policy: CertificatePolicy::emergency(),
			allow_import: false,
			import_certificates: Vec::new(),
			load_error: None,
		}
	}

	pub(super) fn emergency_after(error: String) -> Self {
		Self {
			load_error: Some(error),
			..Self::emergency()
		}
	}
}