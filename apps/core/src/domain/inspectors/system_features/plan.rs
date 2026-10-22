/*
 * File: plan.rs                                                               *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\system_features\plan.rs *
 * Project: system_features                                                    *
 * Author: pi-maaster77                                                        *
 * Created Date: Mo/10/2026 01:20:14                                           *
 * Last Modified: Thu Oct 22 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use std::collections::BTreeMap;
use tracing::warn;
use windows_features::FeatureState;

use crate::config::inspectors::{FeatureDesiredState, SystemFeaturesPolicy};

use super::snapshot::SystemFeaturesSnapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureAction {
    EnableFeature(String),
    DisableFeature(String),
    AddCapability(String),
    RemoveCapability(String),
}

/// Strips the trailing build-specific version from a capability identity string.
///
/// DISM capability identities are formatted as `Name~Arch~Lang~Version`, where segments
/// can be omitted resulting in sequences of `~` (e.g. `Browser.InternetExplorer~~~~0.0.11.0`
/// or `Language.Basic~~~es-MX~0.0.1.0`). This function removes the version segment and
/// any trailing delimiters, returning e.g. `Browser.InternetExplorer` or `Language.Basic~~~es-MX`.
pub fn strip_capability_version(name: &str) -> String {
    let mut trimmed = name;
    if let Some((prefix, last)) = name.rsplit_once('~') {
        let is_version = !last.is_empty()
            && last.chars().next().map_or(false, |c| c.is_ascii_digit())
            && last.chars().all(|c| c.is_ascii_digit() || c == '.');
        if is_version {
            trimmed = prefix;
        }
    }
    let without_trailing = trimmed.trim_end_matches('~');
    if without_trailing.is_empty() {
        trimmed.to_string()
    } else {
        without_trailing.to_string()
    }
}

/// Checks if running inside a virtual machine to prevent enabling features that cause fatal boot crashes.
pub fn is_running_in_virtual_machine() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let bios = hklm
        .open_subkey("HARDWARE\\Description\\System\\BIOS")
        .ok()?;
    let manufacturer: String = bios.get_value("SystemManufacturer").unwrap_or_default();
    let product: String = bios.get_value("SystemProductName").unwrap_or_default();
    let combined = format!("{manufacturer} {product}").to_ascii_lowercase();

    let vm_indicators = [
        "virtualbox",
        "vmware",
        "qemu",
        "kvm",
        "virtual machine",
        "bochs",
        "xen",
        "parallels",
        "innotek",
    ];

    for indicator in vm_indicators {
        if combined.contains(indicator) {
            return Some(format!("{manufacturer} - {product}").trim().to_string());
        }
    }
    None
}

/// Returns a reason if removing or disabling this capability would jeopardize system boot or critical OS services.
pub fn is_boot_critical_capability(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("storagemanagement") {
        return Some(
            "la administración de almacenamiento es indispensable para montar discos y volúmenes (evita INACCESSIBLE_BOOT_DEVICE)",
        );
    }
    if lower.starts_with("language.basic") {
        return Some(
            "los paquetes de idioma base son requeridos por winlogon y el subsistema de inicio de sesión",
        );
    }
    if lower.contains("servercorefonts") || lower.contains("paneuropeansupplementalfonts") {
        return Some(
            "las fuentes base del sistema son requeridas para la consola y componentes visuales esenciales",
        );
    }
    if lower.starts_with("windows.kernel") {
        return Some("los componentes del kernel son indispensables para el inicio de Windows");
    }
    None
}

/// Returns a reason if disabling this optional feature would jeopardize system boot.
pub fn is_boot_critical_feature_disable(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if lower == "client-embeddedbootexp" {
        return Some("el paquete de arranque es crítico para el cargador de Windows");
    }
    None
}

/// Returns a reason if enabling this optional feature is dangerous in the current environment.
pub fn is_dangerous_feature_enable(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    if lower == "microsoft-hyper-v-hypervisor" || lower == "hostguardian" {
        if let Some(vm_info) = is_running_in_virtual_machine() {
            return Some(format!(
                "el sistema se ejecuta dentro de un entorno virtual ({vm_info}) y activar el hipervisor de Hyper-V sin virtualización anidada provoca BSOD irrecuperable en el arranque"
            ));
        }
    }
    None
}

/// Plans the initial reconciliation against every item listed in Nickel.
pub fn plan_reconciliation(
    snapshot: &SystemFeaturesSnapshot,
    policy: &SystemFeaturesPolicy,
) -> Vec<FeatureAction> {
    let mut actions = Vec::new();

    for (name, desired) in &policy.optional_features {
        let current = find_state_case_insensitive(&snapshot.features, name);
        match (desired, current) {
            (FeatureDesiredState::Enabled, Some(state)) if !state.is_enabled_or_pending() => {
                if let Some(reason) = is_dangerous_feature_enable(name) {
                    warn!(
                        feature = %name,
                        reason = %reason,
                        "Protección de arranque: se omite la activación de la característica peligrosa."
                    );
                    continue;
                }
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (FeatureDesiredState::Enabled, None) => {
                if let Some(reason) = is_dangerous_feature_enable(name) {
                    warn!(
                        feature = %name,
                        reason = %reason,
                        "Protección de arranque: se omite la activación de la característica peligrosa."
                    );
                    continue;
                }
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (FeatureDesiredState::Disabled, Some(state)) if state.is_enabled_or_pending() => {
                if let Some(reason) = is_boot_critical_feature_disable(name) {
                    warn!(
                        feature = %name,
                        reason = %reason,
                        "Protección de arranque: se omite la desactivación de la característica crítica."
                    );
                    continue;
                }
                actions.push(FeatureAction::DisableFeature(name.clone()));
            }
            _ => {}
        }
    }

    for (name, desired) in &policy.capabilities {
        let matched = find_capability_state(&snapshot.capabilities, name);
        let current = matched.map(|(_, state)| state);
        let dispatch_name = matched
            .map(|(real_name, _)| real_name.as_str())
            .unwrap_or(name.as_str());

        match (desired, current) {
            (FeatureDesiredState::Enabled, Some(state)) if !state.is_enabled_or_pending() => {
                actions.push(FeatureAction::AddCapability(dispatch_name.to_string()));
            }
            (FeatureDesiredState::Enabled, None) => {
                actions.push(FeatureAction::AddCapability(dispatch_name.to_string()));
            }
            (FeatureDesiredState::Disabled, Some(state)) if state.is_enabled_or_pending() => {
                if let Some(reason) = is_boot_critical_capability(dispatch_name) {
                    warn!(
                        capability = %dispatch_name,
                        reason = %reason,
                        "Protección de arranque: se omite la eliminación de la capacidad crítica."
                    );
                    continue;
                }
                actions.push(FeatureAction::RemoveCapability(dispatch_name.to_string()));
            }
            _ => {}
        }
    }

    actions
}

pub(super) fn find_state_case_insensitive<'a>(
    map: &'a BTreeMap<String, FeatureState>,
    target: &str,
) -> Option<&'a FeatureState> {
    map.iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(target))
        .map(|(_, state)| state)
}

pub(super) fn find_capability_state<'a>(
    map: &'a BTreeMap<String, FeatureState>,
    target: &str,
) -> Option<(&'a String, &'a FeatureState)> {
    if let Some(entry) = map.iter().find(|(k, _)| k.eq_ignore_ascii_case(target)) {
        return Some(entry);
    }
    let normalized_target = strip_capability_version(target);
    map.iter().find(|(candidate, _)| {
        strip_capability_version(candidate).eq_ignore_ascii_case(&normalized_target)
    })
}

pub(super) fn find_desired_state(
    desired_states: &BTreeMap<String, FeatureDesiredState>,
    name: &str,
) -> Option<FeatureDesiredState> {
    desired_states
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, state)| *state)
}

pub(super) fn find_desired_capability_state(
    desired_states: &BTreeMap<String, FeatureDesiredState>,
    name: &str,
) -> Option<FeatureDesiredState> {
    if let Some((_, state)) = desired_states
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
    {
        return Some(*state);
    }
    let normalized_name = strip_capability_version(name);
    desired_states
        .iter()
        .find(|(candidate, _)| {
            strip_capability_version(candidate).eq_ignore_ascii_case(&normalized_name)
        })
        .map(|(_, state)| *state)
}

pub(super) fn plan_changed_reconciliation(
    previous: &SystemFeaturesSnapshot,
    current: &SystemFeaturesSnapshot,
    policy: &SystemFeaturesPolicy,
) -> Vec<FeatureAction> {
    let mut actions = Vec::new();

    for (name, current_state) in &current.features {
        let Some(previous_state) = find_state_case_insensitive(&previous.features, name) else {
            continue;
        };
        let was_enabled = previous_state.is_enabled_or_pending();
        let is_enabled = current_state.is_enabled_or_pending();
        if was_enabled == is_enabled {
            continue;
        }
        match (
            find_desired_state(&policy.optional_features, name),
            is_enabled,
        ) {
            (Some(FeatureDesiredState::Enabled), false) => {
                if let Some(reason) = is_dangerous_feature_enable(name) {
                    warn!(
                        feature = %name,
                        reason = %reason,
                        "Protección de arranque: se omite la activación de la característica peligrosa."
                    );
                    continue;
                }
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (Some(FeatureDesiredState::Disabled), true) => {
                if let Some(reason) = is_boot_critical_feature_disable(name) {
                    warn!(
                        feature = %name,
                        reason = %reason,
                        "Protección de arranque: se omite la desactivación de la característica crítica."
                    );
                    continue;
                }
                actions.push(FeatureAction::DisableFeature(name.clone()));
            }
            _ => {}
        }
    }

    for (name, current_state) in &current.capabilities {
        let Some(previous_state) = find_state_case_insensitive(&previous.capabilities, name) else {
            continue;
        };
        let was_enabled = previous_state.is_enabled_or_pending();
        let is_enabled = current_state.is_enabled_or_pending();
        if was_enabled == is_enabled {
            continue;
        }
        match (
            find_desired_capability_state(&policy.capabilities, name),
            is_enabled,
        ) {
            (Some(FeatureDesiredState::Enabled), false) => {
                actions.push(FeatureAction::AddCapability(name.clone()));
            }
            (Some(FeatureDesiredState::Disabled), true) => {
                if let Some(reason) = is_boot_critical_capability(name) {
                    warn!(
                        capability = %name,
                        reason = %reason,
                        "Protección de arranque: se omite la eliminación de la capacidad crítica."
                    );
                    continue;
                }
                actions.push(FeatureAction::RemoveCapability(name.clone()));
            }
            _ => {}
        }
    }

    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_plan_reconciles_only_registered_items() {
        let snapshot = SystemFeaturesSnapshot {
            features: BTreeMap::from([
                ("FeatureA".to_string(), FeatureState::NotPresent),
                ("FeatureB".to_string(), FeatureState::Installed),
            ]),
            capabilities: BTreeMap::new(),
        };
        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::from([
                ("FeatureA".to_string(), FeatureDesiredState::Enabled),
                ("FeatureB".to_string(), FeatureDesiredState::Disabled),
            ]),
            capabilities: BTreeMap::new(),
        };

        assert_eq!(
            plan_reconciliation(&snapshot, &policy),
            vec![
                FeatureAction::EnableFeature("FeatureA".to_string()),
                FeatureAction::DisableFeature("FeatureB".to_string()),
            ]
        );
    }

    #[test]
    fn changed_plan_only_corrects_managed_transitions() {
        let previous = SystemFeaturesSnapshot {
            features: BTreeMap::from([
                ("managed-enabled".to_string(), FeatureState::Installed),
                ("managed-disabled".to_string(), FeatureState::NotPresent),
                ("unmanaged".to_string(), FeatureState::NotPresent),
            ]),
            capabilities: BTreeMap::new(),
        };
        let current = SystemFeaturesSnapshot {
            features: BTreeMap::from([
                ("managed-enabled".to_string(), FeatureState::NotPresent),
                ("managed-disabled".to_string(), FeatureState::Installed),
                ("unmanaged".to_string(), FeatureState::NotPresent),
            ]),
            capabilities: BTreeMap::new(),
        };
        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::from([
                ("managed-enabled".to_string(), FeatureDesiredState::Enabled),
                (
                    "managed-disabled".to_string(),
                    FeatureDesiredState::Disabled,
                ),
                ("unmanaged".to_string(), FeatureDesiredState::Enabled),
            ]),
            capabilities: BTreeMap::new(),
        };

        assert_eq!(
            plan_changed_reconciliation(&previous, &current, &policy),
            vec![
                FeatureAction::DisableFeature("managed-disabled".to_string()),
                FeatureAction::EnableFeature("managed-enabled".to_string()),
            ]
        );
    }

    #[test]
    fn test_strip_capability_version() {
        assert_eq!(
            strip_capability_version("Browser.InternetExplorer~~~~0.0.11.0"),
            "Browser.InternetExplorer"
        );
        assert_eq!(
            strip_capability_version("Language.Basic~~~es-MX~0.0.1.0"),
            "Language.Basic~~~es-MX"
        );
        assert_eq!(
            strip_capability_version("Language.Basic~~~en-US~0.0.1.0"),
            "Language.Basic~~~en-US"
        );
        assert_eq!(
            strip_capability_version("OpenSSH.Client~~~~0.0.1.0"),
            "OpenSSH.Client"
        );
        assert_eq!(strip_capability_version("NetFX3~~~~"), "NetFX3");
        assert_eq!(
            strip_capability_version("Language.Fonts.PanEuropeanSupplementalFonts~~~~0.0.1.0"),
            "Language.Fonts.PanEuropeanSupplementalFonts"
        );
        assert_eq!(
            strip_capability_version("Browser.InternetExplorer"),
            "Browser.InternetExplorer"
        );
        assert_eq!(
            strip_capability_version("Language.Basic~~~es-MX"),
            "Language.Basic~~~es-MX"
        );
    }

    #[test]
    fn capability_matching_without_version_uses_full_dism_name() {
        let snapshot = SystemFeaturesSnapshot {
            features: BTreeMap::new(),
            capabilities: BTreeMap::from([
                (
                    "Browser.InternetExplorer~~~~0.0.11.0".to_string(),
                    FeatureState::Installed,
                ),
                (
                    "OpenSSH.Client~~~~0.0.1.0".to_string(),
                    FeatureState::NotPresent,
                ),
            ]),
        };
        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::new(),
            capabilities: BTreeMap::from([
                (
                    "Browser.InternetExplorer".to_string(),
                    FeatureDesiredState::Disabled,
                ),
                ("OpenSSH.Client".to_string(), FeatureDesiredState::Enabled),
            ]),
        };

        let actions = plan_reconciliation(&snapshot, &policy);
        assert_eq!(
            actions,
            vec![
                FeatureAction::RemoveCapability("Browser.InternetExplorer~~~~0.0.11.0".to_string()),
                FeatureAction::AddCapability("OpenSSH.Client~~~~0.0.1.0".to_string()),
            ]
        );
    }

    #[test]
    fn boot_protection_prevents_removal_of_critical_capabilities() {
        let snapshot = SystemFeaturesSnapshot {
            features: BTreeMap::new(),
            capabilities: BTreeMap::from([
                (
                    "Microsoft.Windows.StorageManagement~~~~0.0.1.0".to_string(),
                    FeatureState::Installed,
                ),
                (
                    "Language.Basic~~~en-US~0.0.1.0".to_string(),
                    FeatureState::Installed,
                ),
                (
                    "Browser.InternetExplorer~~~~0.0.11.0".to_string(),
                    FeatureState::Installed,
                ),
            ]),
        };
        let policy = SystemFeaturesPolicy {
            optional_features: BTreeMap::new(),
            capabilities: BTreeMap::from([
                (
                    "Microsoft.Windows.StorageManagement".to_string(),
                    FeatureDesiredState::Disabled,
                ),
                (
                    "Language.Basic~~~en-US".to_string(),
                    FeatureDesiredState::Disabled,
                ),
                (
                    "Browser.InternetExplorer".to_string(),
                    FeatureDesiredState::Disabled,
                ),
            ]),
        };

        let actions = plan_reconciliation(&snapshot, &policy);
        // Only InternetExplorer can be removed; StorageManagement and Language.Basic are skipped by boot protection!
        assert_eq!(
            actions,
            vec![FeatureAction::RemoveCapability(
                "Browser.InternetExplorer~~~~0.0.11.0".to_string()
            )]
        );
    }
}
