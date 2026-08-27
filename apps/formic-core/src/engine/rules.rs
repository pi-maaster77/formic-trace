/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/engine/rules.rs
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

use crate::shared::models::{EngineDecision, FileAction, FileEvent};

pub struct RuleEngine;

impl RuleEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, event: &FileEvent) -> EngineDecision {
        // Lógica inicial: Whitelist o filtro por extensiones/rutas
        if let Some(ext) = event.path.extension() {
            if ext == "exe" || ext == "dll" {
                match event.action {
                    FileAction::Created | FileAction::Modified => {
                        println!("[Engine] ¡Atención! Binario detectado: {:?}", event.path);
                        return EngineDecision::Audit;
                    }
                    _ => {}
                }
            }
        }

        EngineDecision::Allow
    }
}