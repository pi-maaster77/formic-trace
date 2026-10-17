/*
 * File: inspectors.rs                                                         *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\config\inspectors.rs           *
 * Project: config                                                             *
 * Author: pi-maaster77                                                        *
 * Created Date: We/10/2026 15:44:20                                           *
 * Last Modified: Sat Oct 17 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

//! Loads, validates, and resolves the Nickel configuration for certificate inspection.

use anyhow::{bail, Context, Result};
use nickel_lang::{Context as NickelContext, ErrorFormat as NickelErrorFormat};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

mod policy;

pub use policy::{CertificateConfig, CertificateMode, CertificatePolicy};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

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

pub fn load_certificate_config(config_path: &Path) -> CertificateConfig {
	match load_policy(config_path) {
		Ok(config) => config,
		Err(error) => CertificateConfig::emergency_after(format!("{error:#}")),
	}
}

fn load_policy(config_path: &Path) -> Result<CertificateConfig> {
	let source_path = config_path
		.canonicalize()
		.with_context(|| format!("no se encuentra la configuración {}", config_path.display()))?;
	let source = fs::read_to_string(&source_path)
		.with_context(|| format!("no se pudo leer {}", source_path.display()))?;
	let mut context = NickelContext::new().with_source_name(source_path.display().to_string());
	let expression = context
		.eval_deep(&source)
		.map_err(|error| anyhow::anyhow!(format_nickel_error(error)))?;
	let root = expression
		.to_serde::<NickelRootConfig>()
		.context("la salida evaluada por Nickel no cumple el esquema esperado")?;

	build_certificate_config(root, &source_path)
}

fn format_nickel_error(error: nickel_lang::Error) -> String {
	let mut formatted = Vec::new();
	if error
		.format(&mut formatted, NickelErrorFormat::Text)
		.is_ok()
	{
		String::from_utf8_lossy(&formatted).into_owned()
	} else {
		format!("{error:?}")
	}
}

#[cfg(test)]
fn parse_policy_json(json: &[u8], config_path: &Path) -> Result<CertificateConfig> {
	let root: NickelRootConfig = serde_json::from_slice(json)
		.context("la salida de Nickel no cumple el esquema JSON esperado")?;
	build_certificate_config(root, config_path)
}

fn build_certificate_config(root: NickelRootConfig, config_path: &Path) -> Result<CertificateConfig> {
	if root.schema_version != 1 {
		bail!("versión de esquema no soportada: {}", root.schema_version);
	}

	let config = root.inspectors.certs;
	if config.mode != CertificateMode::AlertOnly && !config.allow_destructive {
		bail!("los modos que borran certificados requieren allow_destructive = true");
	}
	if !config.import_certificates.is_empty() {
		if !config.allow_import {
			bail!("import_certificates requiere allow_import = true");
		}
		if !config.allow_destructive {
			bail!("la importación modifica LocalMachine\\Root y requiere allow_destructive = true");
		}
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
		load_error: None,
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

