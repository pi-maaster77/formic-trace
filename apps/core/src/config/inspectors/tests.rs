use super::{load_policy, parse_policy_json, CertificateMode};
use std::path::{Path, PathBuf};

#[test]
fn evaluates_repository_nickel_config_in_process() {
	let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/default.ncl");
	let config = load_policy(&config_path).unwrap();

	assert_eq!(config.policy.mode(), CertificateMode::AlertOnly);
	assert!(!config.allow_import);
	assert!(config.import_certificates.is_empty());
}

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
	value["inspectors"]["certs"]["allow_issuer_name_sha256"] = serde_json::json!([issuer_hash]);
	let policy = parse_policy_json(value.to_string().as_bytes(), Path::new("config/default.ncl"))
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
	value["inspectors"]["certs"]["allow_issuer_name_sha256"] = serde_json::json!([issuer_hash]);
	value["inspectors"]["certs"]["deny_sha256"] = serde_json::json!([thumbprint]);
	let policy = parse_policy_json(value.to_string().as_bytes(), Path::new("config/default.ncl"))
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
fn alert_only_can_import_when_both_flags_are_explicit() {
	let mut value: serde_json::Value = serde_json::from_slice(&config("alert_only", true)).unwrap();
	value["inspectors"]["certs"]["allow_import"] = serde_json::Value::Bool(true);
	value["inspectors"]["certs"]["import_certificates"] =
		serde_json::json!(["third_party/test_malicious.cer"]);
	let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/default.ncl");

	let loaded = parse_policy_json(value.to_string().as_bytes(), &config_path).unwrap();
	assert_eq!(loaded.policy.mode(), CertificateMode::AlertOnly);
	assert_eq!(loaded.import_certificates.len(), 1);
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
			"allow_issuer_name_sha256": [],
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