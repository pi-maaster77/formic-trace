/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/notifier.rs
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

use crate::shared::models::{FileEvent, RuleAction};

pub fn notify_event(event: &FileEvent, rule_name: &str, action: &RuleAction) {
    match action {
        RuleAction::Block => {
            eprintln!(
                "[ALERTA DE SEGURIDAD] Operación BLOQUEADA en {:?} por la regla '{}'",
                event.path, rule_name
            );
        }
        RuleAction::Warn => {
            println!(
                "[ADVERTENCIA] Actividad sospechosa en {:?} (Regla: '{}')",
                event.path, rule_name
            );
        }
        RuleAction::Allow => {}
    }
}