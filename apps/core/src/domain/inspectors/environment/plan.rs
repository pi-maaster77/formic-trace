/*
 * File: plan.rs                                                               *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\environment\plan.rs *
 * Project: environment                                                        *
 * Author: pi-maaster77                                                        *
 * Created Date: Mo/10/2026 01:20:52                                           *
 * Last Modified: Thu Oct 22 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use crate::config::inspectors::EnvironmentMode;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReconciliationAction {
    Delete(String),
    Set(String, String),
}

pub(super) fn plan_reconciliation(
    current: &BTreeMap<String, String>,
    allowed: &BTreeMap<String, String>,
    delete_names: &[String],
    mode: EnvironmentMode,
    allow_destructive: bool,
) -> Vec<ReconciliationAction> {
    let mut actions = Vec::new();

    for (name, value) in current {
        let declared = find_variable(allowed, name);
        let should_delete = allow_destructive
            && match mode {
                EnvironmentMode::Subtractive => declared.is_none(),
                EnvironmentMode::Direct => declared.is_none(),
                EnvironmentMode::SelectiveDelete => delete_names
                    .iter()
                    .any(|delete_name| delete_name.eq_ignore_ascii_case(name)),
                EnvironmentMode::Additive => false,
            };

        if should_delete {
            actions.push(ReconciliationAction::Delete(name.clone()));
            continue;
        }

        match declared {
            Some((declared_name, declared_value))
                if mode == EnvironmentMode::Direct && value != declared_value =>
            {
                actions.push(ReconciliationAction::Set(
                    declared_name.clone(),
                    declared_value.clone(),
                ));
            }
            Some(_) | None => {}
        }
    }

    if matches!(mode, EnvironmentMode::Additive | EnvironmentMode::Direct) {
        for (declared_name, declared_value) in allowed {
            if find_variable(current, declared_name).is_none() {
                actions.push(ReconciliationAction::Set(
                    declared_name.clone(),
                    declared_value.clone(),
                ));
            }
        }
    }

    actions
}

pub(super) fn find_variable<'a>(
    variables: &'a BTreeMap<String, String>,
    name: &str,
) -> Option<(&'a String, &'a String)> {
    variables
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn additive_mode_preserves_undeclared_variables() {
        let current = BTreeMap::from([
            ("Path".to_string(), "system-path".to_string()),
            ("TEMP".to_string(), "temp-dir".to_string()),
        ]);

        assert_eq!(
            plan_reconciliation(
                &current,
                &BTreeMap::new(),
                &[],
                EnvironmentMode::Additive,
                false,
            ),
            Vec::<ReconciliationAction>::new()
        );
    }

    #[test]
    fn additive_mode_does_not_overwrite_existing_values() {
        let current = BTreeMap::from([("MODE".to_string(), "existing".to_string())]);
        let desired = BTreeMap::from([("MODE".to_string(), "configured".to_string())]);

        assert!(
            plan_reconciliation(&current, &desired, &[], EnvironmentMode::Additive, false,)
                .is_empty()
        );
    }

    #[test]
    fn reconciliation_restores_changes_and_missing_declared_values() {
        let current = BTreeMap::from([
            ("Path".to_string(), "tampered".to_string()),
            ("REMOVE".to_string(), "not-allowed".to_string()),
        ]);
        let allowed = BTreeMap::from([
            ("PATH".to_string(), "declared-path".to_string()),
            ("MODE".to_string(), "strict".to_string()),
        ]);

        assert_eq!(
            plan_reconciliation(&current, &allowed, &[], EnvironmentMode::Direct, true,),
            vec![
                ReconciliationAction::Set("PATH".to_string(), "declared-path".to_string()),
                ReconciliationAction::Delete("REMOVE".to_string()),
                ReconciliationAction::Set("MODE".to_string(), "strict".to_string()),
            ]
        );
    }

    #[test]
    fn destructive_modes_preserve_variables_without_explicit_authorization() {
        let current = BTreeMap::from([("PATH".to_string(), "system-path".to_string())]);
        let allowed = BTreeMap::new();

        assert!(plan_reconciliation(
            &current,
            &allowed,
            &["PATH".to_string()],
            EnvironmentMode::SelectiveDelete,
            false,
        )
        .is_empty());
        assert!(
            plan_reconciliation(&current, &allowed, &[], EnvironmentMode::Direct, false,)
                .is_empty()
        );
    }

    #[test]
    fn selective_delete_removes_only_explicitly_named_variables() {
        let current = BTreeMap::from([
            ("PATH".to_string(), "system-path".to_string()),
            ("TEMP".to_string(), "temp-dir".to_string()),
        ]);

        assert_eq!(
            plan_reconciliation(
                &current,
                &BTreeMap::new(),
                &["temp".to_string()],
                EnvironmentMode::SelectiveDelete,
                true,
            ),
            vec![ReconciliationAction::Delete("TEMP".to_string())]
        );
    }
}
