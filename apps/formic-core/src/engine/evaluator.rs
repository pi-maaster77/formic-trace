/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/engine/evaluator.rs
* 
* Copyright (C) 2026 pi-maaster77 and Formic Trace Contributors
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

use crate::shared::models::{Config, FileEvent, RuleAction};

pub struct PolicyDecision<'a> {
    pub action: RuleAction,
    pub matched_rule: Option<&'a str>,
}

pub fn evaluate<'a>(event: &FileEvent, config: &'a Config) -> PolicyDecision<'a> {
    let path_str = event.path.to_string_lossy();

    for rule in &config.rules {
        if path_str.contains(&rule.path_pattern) {
            return PolicyDecision {
                action: rule.action.clone(),
                matched_rule: Some(&rule.name),
            };
        }
    }

    PolicyDecision {
        action: config.default_action.clone(),
        matched_rule: None,
    }
}