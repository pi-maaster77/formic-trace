/*
 * File: system_features.rs                                                    *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\config\inspectors\system_features.rs *
 * Project: inspectors                                                         *
 * Author: pi-maaster77                                                        *
 * Created Date: Su/10/2026                                                    *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use anyhow::{bail, Context, Result};
use nickel_lang::Context as NickelContext;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use super::nickel::format_nickel_error;

#[derive(Debug, Deserialize)]
struct NickelRootSystemFeaturesConfig {
    schema_version: u32,
    inspectors: NickelInspectorsSystemFeatures,
}

#[derive(Debug, Deserialize)]
struct NickelInspectorsSystemFeatures {
    system_features: SystemFeaturesPolicy,
}

/// The desired state for a Windows feature or capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredState {
    /// The feature or capability must be enabled/installed.
    Enabled,
    /// The feature or capability must be disabled/removed.
    Disabled,
}

impl<'de> Deserialize<'de> for DesiredState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DesiredStateVisitor;

        impl<'de> serde::de::Visitor<'de> for DesiredStateVisitor {
            type Value = DesiredState;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a boolean or a legacy feature state")
            }

            fn visit_bool<E>(self, value: bool) -> std::result::Result<DesiredState, E>
            where
                E: serde::de::Error,
            {
                Ok(if value {
                    DesiredState::Enabled
                } else {
                    DesiredState::Disabled
                })
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<DesiredState, E>
            where
                E: serde::de::Error,
            {
                match value.trim().to_ascii_lowercase().as_str() {
                    "enabled" | "enable" | "present" | "installed" | "pending" => {
                        Ok(DesiredState::Enabled)
                    }
                    "disabled"
                    | "disable"
                    | "absent"
                    | "uninstalled"
                    | "not_present"
                    | "uninstall_pending"
                    | "staged"
                    | "removed"
                    | "resolved"
                    | "install_pending"
                    | "superseded"
                    | "partially_installed" => Ok(DesiredState::Disabled),
                    other => Err(E::custom(format!(
                        "estado desconocido: '{other}', se esperaba true o false"
                    ))),
                }
            }

            fn visit_enum<A>(self, data: A) -> std::result::Result<DesiredState, A::Error>
            where
                A: serde::de::EnumAccess<'de>,
            {
                use serde::de::VariantAccess;
                let (variant, access) = data.variant::<String>()?;
                access.unit_variant()?;
                self.visit_str(&variant)
            }
        }

        deserializer.deserialize_any(DesiredStateVisitor)
    }
}

/// Declarative policy defining the desired states for Windows Optional Features and Capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SystemFeaturesPolicy {
    /// Desired state for Windows Optional Features (e.g. `Microsoft-Windows-Subsystem-Linux`, `NetFx3`).
    #[serde(default)]
    pub optional_features: BTreeMap<String, DesiredState>,
    /// Desired state for Windows Capabilities (e.g. `OpenSSH.Client`, `Browser.InternetExplorer`).
    #[serde(default)]
    pub capabilities: BTreeMap<String, DesiredState>,
}

/// Evaluates `config/default.ncl` and returns the validated system features policy.
pub fn load_system_features_policy(config_path: &Path) -> Result<SystemFeaturesPolicy> {
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
        .to_serde::<NickelRootSystemFeaturesConfig>()
        .context("la salida evaluada por Nickel no contiene una política de características del sistema válida")?;

    if root.schema_version != 1 {
        bail!("versión de esquema no soportada: {}", root.schema_version);
    }

    validate_items(
        "características opcionales",
        &root.inspectors.system_features.optional_features,
    )?;
    validate_items("capacidades", &root.inspectors.system_features.capabilities)?;

    Ok(root.inspectors.system_features)
}

fn validate_items(category: &str, items: &BTreeMap<String, DesiredState>) -> Result<()> {
    let mut normalized_names = HashSet::new();
    for name in items.keys() {
        if name.trim().is_empty() {
            bail!("nombre de {category} vacío no permitido");
        }
        if name.contains('\0') {
            bail!("nombre de {category} con caracteres nulos no permitido: {name:?}");
        }
        if !normalized_names.insert(name.to_ascii_uppercase()) {
            bail!("nombre de {category} duplicado sin distinguir mayúsculas: {name}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn loads_system_features_policy_from_repository_nickel() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/default.ncl");
        let policy = load_system_features_policy(&config_path).unwrap();
        assert_eq!(
            policy.optional_features.get("NetFx3"),
            Some(&DesiredState::Enabled)
        );
        assert_eq!(
            policy.capabilities.get("OpenSSH.Client"),
            Some(&DesiredState::Enabled)
        );
        assert!(policy.optional_features.len() > 100);
        assert!(policy.capabilities.len() > 400);
    }

    #[test]
    fn desired_state_accepts_boolean_values() {
        assert_eq!(
            serde_json::from_str::<DesiredState>("true").unwrap(),
            DesiredState::Enabled
        );
        assert_eq!(
            serde_json::from_str::<DesiredState>("false").unwrap(),
            DesiredState::Disabled
        );
    }

    #[test]
    fn validates_feature_names() {
        let valid = BTreeMap::from([
            (
                "Microsoft-Windows-Subsystem-Linux".to_string(),
                DesiredState::Enabled,
            ),
            ("NetFx3".to_string(), DesiredState::Enabled),
        ]);
        assert!(validate_items("características opcionales", &valid).is_ok());

        let empty = BTreeMap::from([("".to_string(), DesiredState::Enabled)]);
        assert!(validate_items("características opcionales", &empty).is_err());

        let null_byte = BTreeMap::from([("NetFx3\0Bad".to_string(), DesiredState::Enabled)]);
        assert!(validate_items("características opcionales", &null_byte).is_err());

        let duplicate = BTreeMap::from([
            ("NetFx3".to_string(), DesiredState::Enabled),
            ("NETFX3".to_string(), DesiredState::Disabled),
        ]);
        assert!(validate_items("características opcionales", &duplicate).is_err());
    }
}
