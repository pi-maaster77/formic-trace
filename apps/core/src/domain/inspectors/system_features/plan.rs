use std::collections::BTreeMap;
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
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (FeatureDesiredState::Enabled, None) => {
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (FeatureDesiredState::Disabled, Some(state)) if state.is_enabled_or_pending() => {
                actions.push(FeatureAction::DisableFeature(name.clone()));
            }
            _ => {}
        }
    }

    for (name, desired) in &policy.capabilities {
        let current = find_state_case_insensitive(&snapshot.capabilities, name);
        match (desired, current) {
            (FeatureDesiredState::Enabled, Some(state)) if !state.is_enabled_or_pending() => {
                actions.push(FeatureAction::AddCapability(name.clone()));
            }
            (FeatureDesiredState::Enabled, None) => {
                actions.push(FeatureAction::AddCapability(name.clone()));
            }
            (FeatureDesiredState::Disabled, Some(state)) if state.is_enabled_or_pending() => {
                actions.push(FeatureAction::RemoveCapability(name.clone()));
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

pub(super) fn find_desired_state(
    desired_states: &BTreeMap<String, FeatureDesiredState>,
    name: &str,
) -> Option<FeatureDesiredState> {
    desired_states
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
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
                actions.push(FeatureAction::EnableFeature(name.clone()));
            }
            (Some(FeatureDesiredState::Disabled), true) => {
                actions.push(FeatureAction::DisableFeature(name.clone()));
            }
            _ => {}
        }
    }

    for (name, current_state) in &current.capabilities {
        let Some(previous_state) = find_state_case_insensitive(&previous.capabilities, name)
        else {
            continue;
        };
        let was_enabled = previous_state.is_enabled_or_pending();
        let is_enabled = current_state.is_enabled_or_pending();
        if was_enabled == is_enabled {
            continue;
        }
        match (find_desired_state(&policy.capabilities, name), is_enabled) {
            (Some(FeatureDesiredState::Enabled), false) => {
                actions.push(FeatureAction::AddCapability(name.clone()));
            }
            (Some(FeatureDesiredState::Disabled), true) => {
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
}

