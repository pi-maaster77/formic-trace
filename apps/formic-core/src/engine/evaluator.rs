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

use crate::config::FormicConfig;
use crate::shared::models::{PolicyDecision, SystemEvent};

pub fn evaluate<'a>(event: &'a SystemEvent, config: &'a FormicConfig) -> PolicyDecision<'a> {
    match event {
        SystemEvent::File(file_event) => {
            let path_str = file_event.path.to_string_lossy();
            for rule in &config.rules {
                if path_str.contains(&rule.path_pattern) {
                    return PolicyDecision {
                        action: rule.action.clone(),
                        matched_rule: Some(&rule.name),
                    };
                }
            }
        }
        SystemEvent::Process(proc_event) => {
            let exe_str = proc_event.path.to_string_lossy();
            for rule in &config.rules {
                if exe_str.contains(&rule.path_pattern) {
                    return PolicyDecision {
                        action: rule.action.clone(),
                        matched_rule: Some(&rule.name),
                    };
                }
            }
        }
        SystemEvent::Registry(_reg_event) => {}
        SystemEvent::Net(_net_event) => {}
    }

    PolicyDecision {
        action: config.default_action.clone(),
        matched_rule: None,
    }
}
