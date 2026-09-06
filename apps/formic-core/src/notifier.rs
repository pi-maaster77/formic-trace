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

use crate::shared::models::{RuleAction, SystemEvent};

pub fn notify_event(event: &SystemEvent, rule_name: &str, action: &RuleAction) {
    let title = match action {
        RuleAction::Block => "Formic Trace - Evento Bloqueado",
        RuleAction::Warn => "Formic Trace - Advertencia de Seguridad",
        RuleAction::Allow => "Formic Trace - Evento Permitido",
    };

    let details = match event {
        SystemEvent::File(e) => format!("Archivo: {:?}\nAcción: {:?}", e.path, e.action),
        SystemEvent::Process(e) => format!("Proceso: {:?}\nPID: {}\nCMD: {}", e.path, e.pid, e.command_line),
        SystemEvent::Registry(e) => format!("Registro: {}\nClave: {}", e.key_path, e.value_name),
        SystemEvent::Net(e) => format!("Red: {}:{} ({})", e.remote_addr, e.remote_port, e.protocol),
    };

    let message = format!("Regla: {}\n{}", rule_name, details);

    println!("[NOTIFIER] [{}] {}", title, message.replace('\n', " | "));
}