use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use windows_features::DismSession;

use super::snapshot::SystemFeaturesSnapshot;

#[derive(Serialize)]
struct FeatureInventory {
    optional_features: BTreeMap<String, bool>,
    capabilities: BTreeMap<String, bool>,
}

/// Exports the current Windows inventory without applying the Nickel policy.
pub fn dump_features(config_path: &Path) -> Result<PathBuf> {
    let session = DismSession::open_online().context("falló al abrir la sesión online de DISM")?;
    let snapshot = super::read_snapshot_from_session(&session)?;
    let output_path = feature_dump_path(config_path);
    let inventory = FeatureInventory {
        optional_features: snapshot
            .features
            .into_iter()
            .map(|(name, state)| (name, state.is_enabled_or_pending()))
            .collect(),
        capabilities: snapshot
            .capabilities
            .into_iter()
            .map(|(name, state)| (name, state.is_enabled_or_pending()))
            .collect(),
    };
    let contents = toml::to_string_pretty(&inventory)
        .context("no se pudo serializar el inventario de características a TOML")?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("no se pudo crear {}", parent.display()))?;
    }
    fs::write(&output_path, contents)
        .with_context(|| format!("no se pudo escribir {}", output_path.display()))?;

    Ok(output_path)
}

fn feature_dump_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("inspectors")
        .join("system_features")
        .join("features.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_writes_boolean_values_next_to_policy_file() {
        let inventory = FeatureInventory {
            optional_features: BTreeMap::from([
                ("enabled-feature".to_string(), true),
                ("disabled-feature".to_string(), false),
            ]),
            capabilities: BTreeMap::new(),
        };
        let serialized = toml::to_string(&inventory).unwrap();
        let parsed: toml::Value = toml::from_str(&serialized).unwrap();

        assert_eq!(
            parsed["optional_features"]["enabled-feature"].as_bool(),
            Some(true)
        );
        assert_eq!(
            parsed["optional_features"]["disabled-feature"].as_bool(),
            Some(false)
        );
        assert_eq!(
            feature_dump_path(Path::new("config/default.ncl")),
            PathBuf::from("config/inspectors/system_features/features.toml")
        );
    }
}

