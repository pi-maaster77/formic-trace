/*
 * File: environment.rs                                                        *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\config\inspectors\environment.rs *
 * Project: inspectors                                                         *
 * Author: pi-maaster77                                                        *
 * Created Date: Sa/10/2026 03:41:34                                           *
 * Last Modified: Sun Oct 18 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use anyhow::{bail, Context, Result};
use nickel_lang::Context as NickelContext;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use super::nickel::format_nickel_error;

#[derive(Debug, Deserialize)]
struct NickelRootEnvironmentConfig {
    schema_version: u32,
    inspectors: NickelInspectorsEnvironment,
}

#[derive(Debug, Deserialize)]
struct NickelInspectorsEnvironment {
    environment: NickelEnvironmentPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct NickelEnvironmentPolicy {
    mode: String,
    allow_destructive: bool,
    system: BTreeMap<String, String>,
    user: BTreeMap<String, String>,
    delete_system: Vec<String>,
    delete_user: Vec<String>,
}

impl Default for NickelEnvironmentPolicy {
    fn default() -> Self {
        Self {
            mode: "additive".to_string(),
            allow_destructive: false,
            system: BTreeMap::new(),
            user: BTreeMap::new(),
            delete_system: Vec::new(),
            delete_user: Vec::new(),
        }
    }
}

/// Reconciliation mode for persistent environment variables.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentMode {
    Additive,
    Subtractive,
    Direct,
    SelectiveDelete,
}

/// Persistent environment policy for the machine and current user.
#[derive(Debug, PartialEq, Eq)]
pub struct EnvironmentPolicy {
    pub mode: EnvironmentMode,
    pub allow_destructive: bool,
    /// Values stored in `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment`.
    pub system: BTreeMap<String, String>,
    /// Values stored in `HKCU\\Environment` for the account running Formic.
    pub user: BTreeMap<String, String>,
    pub delete_system: Vec<String>,
    pub delete_user: Vec<String>,
}

/// Evaluates `config/default.ncl` and validates the environment allowlists.
pub fn load_environment_policy(config_path: &Path) -> Result<EnvironmentPolicy> {
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
        .to_serde::<NickelRootEnvironmentConfig>()
        .context("la salida evaluada por Nickel no contiene una política de entorno válida")?;

    if root.schema_version != 1 {
        bail!("versión de esquema no soportada: {}", root.schema_version);
    }

    let nickel_policy = root.inspectors.environment;
    let mode = match nickel_policy.mode.as_str() {
        "additive" => EnvironmentMode::Additive,
        "subtractive" => EnvironmentMode::Subtractive,
        "direct" => EnvironmentMode::Direct,
        "selective_delete" => EnvironmentMode::SelectiveDelete,
        _ => bail!("modo de entorno no soportado: {}", nickel_policy.mode),
    };

    validate_scope("system", &nickel_policy.system)?;
    validate_scope("user", &nickel_policy.user)?;
    validate_delete_names("system", &nickel_policy.delete_system)?;
    validate_delete_names("user", &nickel_policy.delete_user)?;
    if mode != EnvironmentMode::SelectiveDelete
        && (!nickel_policy.delete_system.is_empty() || !nickel_policy.delete_user.is_empty())
    {
        bail!("delete_system y delete_user solo se permiten en modo selective_delete");
    }

    Ok(EnvironmentPolicy {
        mode,
        allow_destructive: nickel_policy.allow_destructive,
        system: nickel_policy.system,
        user: nickel_policy.user,
        delete_system: nickel_policy.delete_system,
        delete_user: nickel_policy.delete_user,
    })
}

fn validate_scope(scope: &str, variables: &BTreeMap<String, String>) -> Result<()> {
    let mut normalized_names = HashSet::new();
    for name in variables.keys() {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            bail!("nombre de variable inválido en la política {scope}: {name:?}");
        }
        if !normalized_names.insert(name.to_ascii_uppercase()) {
            bail!("nombre de variable duplicado sin distinguir mayúsculas en {scope}: {name}");
        }
    }
    Ok(())
}

fn validate_delete_names(scope: &str, names: &[String]) -> Result<()> {
    let mut normalized_names = HashSet::new();
    for name in names {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            bail!("nombre de variable inválido en delete_{scope}: {name:?}");
        }
        if !normalized_names.insert(name.to_ascii_uppercase()) {
            bail!("nombre duplicado sin distinguir mayúsculas en delete_{scope}: {name}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{load_environment_policy, validate_delete_names, validate_scope};
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn loads_environment_policy_from_repository_nickel() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/default.ncl");
        let policy = load_environment_policy(&config_path).unwrap();
        assert_eq!(policy.mode, super::EnvironmentMode::Additive);
        assert!(!policy.allow_destructive);
        assert!(policy.system.is_empty());
        assert_eq!(
            policy.user.get("PRUEBA").map(String::as_str),
            Some("ESTOESUNAPRUEBA")
        );
    }

    #[test]
    fn empty_allowlists_are_valid_and_deny_every_variable() {
        assert!(validate_scope("system", &BTreeMap::new()).is_ok());
        assert!(validate_scope("user", &BTreeMap::new()).is_ok());
        assert!(validate_delete_names("user", &[]).is_ok());
    }

    #[test]
    fn rejects_names_that_cannot_be_environment_variables() {
        let variables = BTreeMap::from([("BAD=NAME".to_string(), "value".to_string())]);
        assert!(validate_scope("user", &variables).is_err());
    }

    #[test]
    fn rejects_case_insensitive_duplicate_names() {
        let variables = BTreeMap::from([
            ("Path".to_string(), "one".to_string()),
            ("PATH".to_string(), "two".to_string()),
        ]);
        assert!(validate_scope("user", &variables).is_err());
    }

    #[test]
    fn rejects_case_insensitive_duplicate_delete_names() {
        assert!(validate_delete_names("user", &["Path".into(), "PATH".into()]).is_err());
    }
}
