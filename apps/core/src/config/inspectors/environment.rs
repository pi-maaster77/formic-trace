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
    environment: EnvironmentPolicy,
}

/// Exact persistent environment values allowed per machine and current user.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct EnvironmentPolicy {
    /// Values stored in `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment`.
    pub system: BTreeMap<String, String>,
    /// Values stored in `HKCU\\Environment` for the account running Formic.
    pub user: BTreeMap<String, String>,
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

    validate_scope("system", &root.inspectors.environment.system)?;
    validate_scope("user", &root.inspectors.environment.user)?;
    Ok(root.inspectors.environment)
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

#[cfg(test)]
mod tests {
    use super::{load_environment_policy, validate_scope, EnvironmentPolicy};
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn loads_environment_policy_from_repository_nickel() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/default.ncl");
        let policy = load_environment_policy(&config_path).unwrap();
        assert!(policy.system.is_empty());
        assert_eq!(
            policy.user.get("PRUEBA").map(String::as_str),
            Some("ESTOESUNAPRUEBA")
        );
    }

    #[test]
    fn empty_allowlists_are_valid_and_deny_every_variable() {
        let policy = EnvironmentPolicy {
            system: BTreeMap::new(),
            user: BTreeMap::new(),
        };
        assert!(validate_scope("system", &policy.system).is_ok());
        assert!(validate_scope("user", &policy.user).is_ok());
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
}
