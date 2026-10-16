/*
 * File: inspectors.rs                                                         *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\config\inspectors.rs           *
 * Project: config                                                             *
 * Author: pi-maaster77                                                        *
 * Created Date: We/10/2026 15:44:20                                           *
 * Last Modified: Thu Oct 15 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */


use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateMode {
	Minimal,
	PurgeAll,
	Whitelist,
	Blacklist,
	AlertOnly,
}

#[derive(Debug, Deserialize)]
struct NickelRootConfig {
	schema_version: u32,
	inspectors: NickelInspectors,
	#[serde(default)]
	_policies: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NickelInspectors {
	certs: NickelCertificatePolicy,
	#[serde(flatten)]
	_other_inspectors: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NickelCertificatePolicy {
	mode: CertificateMode,
	baseline_sha256: Vec<String>,
	allow_sha256: Vec<String>,
    allow_issuer_name_sha256: Vec<String>,
	deny_sha256: Vec<String>,
	deny_issuer_name_sha256: Vec<String>,
	allow_destructive: bool,
	allow_import: bool,
	import_certificates: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CertificatePolicy {
	mode: CertificateMode,
	baseline_sha256: HashSet<String>,
	allow_sha256: HashSet<String>,
	allow_issuer_name_sha256: HashSet<String>,
	deny_sha256: HashSet<String>,
	deny_issuer_name_sha256: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct CertificateConfig {
	pub policy: CertificatePolicy,
	pub allow_import: bool,
	pub import_certificates: Vec<PathBuf>,
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
		if self.deny_sha256.contains(thumbprint) || issuer_is_denied
		{
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
		}
	}
}

pub fn load_certificate_config(
	config_path: &Path,
	nickel_binary: &Path,
	) -> CertificateConfig {
	match load_policy(config_path, nickel_binary) {
		Ok(config) => {
			info!(mode = ?config.policy.mode(), path = ?config_path, "Configuración del inspector de certificados cargada.");
			config
		}
		Err(error) => {
			warn!(
				error = %error,
				"No se pudo cargar la política Nickel; se usará el modo de emergencia alert_only."
			);
			CertificateConfig::emergency()
		}
	}
}

fn load_policy(config_path: &Path, nickel_binary: &Path) -> Result<CertificateConfig> {
	let config_directory = config_path
		.parent()
		.filter(|parent| !parent.as_os_str().is_empty())
		.unwrap_or_else(|| Path::new("."));
	let config_file = config_path
		.file_name()
		.context("la ruta de configuración no tiene nombre de archivo")?;

	let output = Command::new(nickel_binary)
		.arg("export")
		.arg(config_file)
		.current_dir(config_directory)
		.output()
		.with_context(|| format!("no se pudo ejecutar Nickel ({})", nickel_binary.display()))?;

	if !output.status.success() {
		bail!(
			"Nickel terminó con {}: {}",
			output.status,
			String::from_utf8_lossy(&output.stderr).trim()
		);
	}

	parse_policy_json(&output.stdout, config_path)
}


fn parse_policy_json(json: &[u8], config_path: &Path) -> Result<CertificateConfig> {
	let root: NickelRootConfig = serde_json::from_slice(json)
		.context("la salida de Nickel no cumple el esquema JSON esperado")?;

	if root.schema_version != 1 {
		bail!("versión de esquema no soportada: {}", root.schema_version);
	}

	let config = root.inspectors.certs;
	if config.mode != CertificateMode::AlertOnly && !config.allow_destructive {
		bail!("los modos que borran certificados requieren allow_destructive = true");
	}
	if !config.allow_import && !config.import_certificates.is_empty() {
		bail!("import_certificates requiere allow_import = true");
	}
	if config.mode == CertificateMode::AlertOnly && !config.import_certificates.is_empty() {
		bail!("alert_only no puede importar certificados ni modificar el almacén");
	}

	let baseline_sha256 = normalize_hashes(config.baseline_sha256, "baseline_sha256")?;
	let allow_sha256 = normalize_hashes(config.allow_sha256, "allow_sha256")?;
	let allow_issuer_name_sha256 = normalize_hashes(
		config.allow_issuer_name_sha256,
		"allow_issuer_name_sha256",
	)?;
	let deny_sha256 = normalize_hashes(config.deny_sha256, "deny_sha256")?;
	let deny_issuer_name_sha256 = normalize_hashes(
		config.deny_issuer_name_sha256,
		"deny_issuer_name_sha256",
	)?;

	match config.mode {
		CertificateMode::Minimal if baseline_sha256.is_empty() => {
			bail!("minimal requiere al menos una huella en baseline_sha256");
		}
		CertificateMode::Whitelist
			if allow_sha256.is_empty() && allow_issuer_name_sha256.is_empty() =>
		{
			bail!("whitelist requiere allow_sha256 o allow_issuer_name_sha256");
		}
		CertificateMode::Blacklist
			if deny_sha256.is_empty() && deny_issuer_name_sha256.is_empty() =>
		{
			bail!("blacklist requiere deny_sha256 o deny_issuer_name_sha256");
		}
		_ => {}
	}

	let config_directory = config_path
		.parent()
		.unwrap_or_else(|| Path::new("."));
	let certificates_directory = config_directory.join("inspectors").join("certs");
	let import_certificates = resolve_import_files(
		&certificates_directory,
		config.import_certificates,
	)?;

	Ok(CertificateConfig {
		policy: CertificatePolicy {
			mode: config.mode,
			baseline_sha256,
			allow_sha256,
			allow_issuer_name_sha256,
			deny_sha256,
			deny_issuer_name_sha256,
		},
		allow_import: config.allow_import,
		import_certificates,
	})
}

fn resolve_import_files(certificates_directory: &Path, files: Vec<String>) -> Result<Vec<PathBuf>> {
	if files.is_empty() {
		return Ok(Vec::new());
	}

	let root = certificates_directory
		.canonicalize()
		.with_context(|| format!("no se encuentra {}", certificates_directory.display()))?;
	let third_party = root.join("third_party").canonicalize().with_context(|| {
		format!("no se encuentra {}", root.join("third_party").display())
	})?;
	let mut resolved = Vec::with_capacity(files.len());

	for file in files {
		let relative = Path::new(&file);
		if relative.is_absolute()
			|| relative.components().any(|part| !matches!(part, Component::Normal(_)))
			|| relative.components().next() != Some(Component::Normal(std::ffi::OsStr::new("third_party")))
		{
			bail!("ruta de certificado fuera de third_party: {file}");
		}

		let extension = relative
			.extension()
			.and_then(|extension| extension.to_str())
			.unwrap_or_default()
			.to_ascii_lowercase();
		if !matches!(extension.as_str(), "cer" | "crt" | "pem") {
			bail!("extensión de certificado no admitida: {file}");
		}

		let path = root.join(relative).canonicalize().with_context(|| {
			format!("no se pudo resolver el certificado {}", relative.display())
		})?;
		if !path.starts_with(&third_party) || !path.is_file() {
			bail!("ruta de certificado no válida: {}", path.display());
		}
		resolved.push(path);
	}

	Ok(resolved)
}

fn normalize_hashes(values: Vec<String>, field: &str) -> Result<HashSet<String>> {
	values
		.into_iter()
		.map(|value| {
			if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
				bail!("{field} contiene una huella que no es SHA-256 hexadecimal: {value}");
			}
			Ok(value.to_ascii_lowercase())
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::{parse_policy_json, CertificateMode};
	use std::path::Path;

	fn config(mode: &str, allow_destructive: bool) -> Vec<u8> {
		serde_json::json!({
			"schema_version": 1,
			"inspectors": { "certs": {
				"mode": mode,
				"baseline_sha256": [],
				"allow_sha256": [],
				"allow_issuer_name_sha256": [],
				"deny_sha256": [],
				"deny_issuer_name_sha256": [],
				"allow_destructive": allow_destructive,
				"allow_import": false,
				"import_certificates": [],
			}},
			"policies": {},
		})
		.to_string()
		.into_bytes()
	}

	#[test]
	fn accepts_alert_only_without_destructive_authorization() {
		let json = config("alert_only", false);
		let config = parse_policy_json(&json, Path::new("config/default.ncl")).unwrap();
		assert_eq!(config.policy.mode(), CertificateMode::AlertOnly);
		assert!(!config.policy.should_delete("", None));
	}

	#[test]
	fn rejects_empty_whitelist() {
		let json = config("whitelist", true);
		assert!(parse_policy_json(&json, Path::new("config/default.ncl")).is_err());
	}

	#[test]
	fn whitelist_can_allow_an_issuer_name_without_certificate_hashes() {
		let issuer_hash = "ab".repeat(32);
		let mut value: serde_json::Value = serde_json::from_slice(&config("whitelist", true)).unwrap();
		value["inspectors"]["certs"]["allow_issuer_name_sha256"] =
			serde_json::json!([issuer_hash]);
		let policy = parse_policy_json(
			value.to_string().as_bytes(),
			Path::new("config/default.ncl"),
		)
		.unwrap()
		.policy;

		assert!(!policy.should_delete("cd", Some(&issuer_hash)));
		assert!(policy.should_delete("cd", Some(&"ef".repeat(32))));
	}

	#[test]
	fn certificate_blacklist_overrides_issuer_whitelist() {
		let issuer_hash = "ab".repeat(32);
		let thumbprint = "cd".repeat(32);
		let mut value: serde_json::Value = serde_json::from_slice(&config("whitelist", true)).unwrap();
		value["inspectors"]["certs"]["allow_issuer_name_sha256"] =
			serde_json::json!([issuer_hash]);
		value["inspectors"]["certs"]["deny_sha256"] = serde_json::json!([thumbprint]);
		let policy = parse_policy_json(
			value.to_string().as_bytes(),
			Path::new("config/default.ncl"),
		)
		.unwrap()
		.policy;

		assert!(policy.should_delete(&thumbprint, Some(&issuer_hash)));
	}

	#[test]
	fn rejects_destructive_mode_without_explicit_opt_in() {
		let json = config("purge_all", false);
		assert!(parse_policy_json(&json, Path::new("config/default.ncl")).is_err());
	}

	#[test]
	fn alert_only_rejects_certificate_imports() {
		let mut value: serde_json::Value = serde_json::from_slice(&config("alert_only", false)).unwrap();
		value["inspectors"]["certs"]["allow_import"] = serde_json::Value::Bool(true);
		value["inspectors"]["certs"]["import_certificates"] =
			serde_json::json!(["third_party/vendor-root.pem"]);
		assert!(parse_policy_json(value.to_string().as_bytes(), Path::new("config/default.ncl")).is_err());
	}

	#[test]
	fn purge_all_deletes_only_after_explicit_opt_in() {
		let json = config("purge_all", true);
		let config = parse_policy_json(&json, Path::new("config/default.ncl")).unwrap();
		assert!(config.policy.should_delete("thumbprint", None));
	}

	#[test]
	fn normalizes_hashes_before_policy_matching() {
		let thumbprint = "ab".repeat(32);
		let json = serde_json::json!({
			"schema_version": 1,
			"inspectors": { "certs": {
				"mode": "minimal",
				"baseline_sha256": [thumbprint.to_ascii_uppercase()],
				"allow_sha256": [],
				"deny_sha256": [],
				"deny_issuer_name_sha256": [],
				"allow_destructive": true,
				"allow_import": false,
				"import_certificates": [],
			}},
			"policies": {},
		});
		let config = parse_policy_json(json.to_string().as_bytes(), Path::new("config/default.ncl")).unwrap();
		assert!(!config.policy.should_delete(&thumbprint, None));
		assert!(config.policy.should_delete(&"cd".repeat(32), None));
	}
}