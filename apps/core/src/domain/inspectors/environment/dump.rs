use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

use super::registry::{read_scope_from_key, SYSTEM_ENVIRONMENT_KEY, USER_ENVIRONMENT_KEY};

#[derive(Serialize)]
struct EnvironmentInventory {
    system: BTreeMap<String, String>,
    user: BTreeMap<String, String>,
}

/// Exports persistent machine and current-user environment values without applying policy.
pub fn dump_environment(output_path: &Path) -> Result<PathBuf> {
    let machine_key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(SYSTEM_ENVIRONMENT_KEY, KEY_READ)
        .context("no se pudo leer el entorno persistente del sistema")?;
    let user_key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(USER_ENVIRONMENT_KEY, KEY_READ)
        .context("no se pudo leer el entorno persistente del usuario")?;

    let inventory = EnvironmentInventory {
        system: read_scope_from_key("system", &machine_key)?,
        user: read_scope_from_key("user", &user_key)?,
    };
    let contents = toml::to_string_pretty(&inventory)
        .context("no se pudo serializar el inventario de entorno a TOML")?;

    if let Some(parent) = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("no se pudo crear {}", parent.display()))?;
    }
    fs::write(output_path, contents)
        .with_context(|| format!("no se pudo escribir {}", output_path.display()))?;

    Ok(output_path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::EnvironmentInventory;
    use std::collections::BTreeMap;

    #[test]
    fn inventory_serializes_both_scopes_as_toml_maps() {
        let inventory = EnvironmentInventory {
            system: BTreeMap::from([("Path".to_string(), "C:\\Windows".to_string())]),
            user: BTreeMap::from([("TEMP".to_string(), "C:\\Temp".to_string())]),
        };
        let serialized = toml::to_string(&inventory).unwrap();
        let parsed: toml::Value = toml::from_str(&serialized).unwrap();

        assert_eq!(parsed["system"]["Path"].as_str(), Some("C:\\Windows"));
        assert_eq!(parsed["user"]["TEMP"].as_str(), Some("C:\\Temp"));
    }
}
