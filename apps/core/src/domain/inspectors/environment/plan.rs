use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReconciliationAction {
    Delete(String),
    Set(String, String),
}

pub(super) fn plan_reconciliation(
    current: &BTreeMap<String, String>,
    allowed: &BTreeMap<String, String>,
) -> Vec<ReconciliationAction> {
    let mut actions = Vec::new();

    for (name, value) in current {
        match find_variable(allowed, name) {
            None => actions.push(ReconciliationAction::Delete(name.clone())),
            Some((declared_name, declared_value)) if value != declared_value => {
                actions.push(ReconciliationAction::Set(
                    declared_name.clone(),
                    declared_value.clone(),
                ));
            }
            Some(_) => {}
        }
    }

    for (declared_name, declared_value) in allowed {
        if find_variable(current, declared_name).is_none() {
            actions.push(ReconciliationAction::Set(
                declared_name.clone(),
                declared_value.clone(),
            ));
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
    fn empty_allowlist_plans_deletion_of_every_variable() {
        let current = BTreeMap::from([
            ("Path".to_string(), "system-path".to_string()),
            ("TEMP".to_string(), "temp-dir".to_string()),
        ]);

        assert_eq!(
            plan_reconciliation(&current, &BTreeMap::new()),
            vec![
                ReconciliationAction::Delete("Path".to_string()),
                ReconciliationAction::Delete("TEMP".to_string()),
            ]
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
            plan_reconciliation(&current, &allowed),
            vec![
                ReconciliationAction::Set("PATH".to_string(), "declared-path".to_string()),
                ReconciliationAction::Delete("REMOVE".to_string()),
                ReconciliationAction::Set("MODE".to_string(), "strict".to_string()),
            ]
        );
    }
}
