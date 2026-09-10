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
use std::path::Path;

/// Normaliza una ruta convirtiéndola a minúsculas, uniformando separadores
/// y mapeando rutas de dispositivo NT (\Device\HarddiskVolumeX) a letras de unidad (C:\).
fn normalize_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('/', "\\").to_lowercase();

    // Mapeo básico de prefijos de volumen NT a letra de unidad C: si aplica
    if raw.starts_with(r"\device\harddiskvolume") {
        if let Some(idx) = raw[21..].find('\\') {
            let rest = &raw[21 + idx..];
            return format!("c:{}", rest);
        }
    }

    raw
}

pub fn evaluate<'a>(event: &'a SystemEvent, config: &'a FormicConfig) -> PolicyDecision<'a> {
    match event {
        SystemEvent::File(file_event) => {
            let normalized_path = normalize_path(&file_event.path);
            for rule in &config.rules {
                if let Some(pattern) = &rule.path_pattern {
                    let normalized_pattern = pattern.replace('/', "\\").to_lowercase();
                    if normalized_path.contains(&normalized_pattern) {
                        return PolicyDecision {
                            action: rule.action.clone(),
                            matched_rule: Some(&rule.name),
                        };
                    }
                }
            }
        }
        SystemEvent::Process(proc_event) => {
            let normalized_exe = normalize_path(&proc_event.path);
            for rule in &config.rules {
                if let Some(pattern) = &rule.path_pattern {
                    let normalized_pattern = pattern.replace('/', "\\").to_lowercase();
                    if normalized_path_matches(&normalized_exe, &normalized_pattern) {
                        return PolicyDecision {
                            action: rule.action.clone(),
                            matched_rule: Some(&rule.name),
                        };
                    }
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

fn normalized_path_matches(exe_path: &str, pattern: &str) -> bool {
    if exe_path.is_empty() {
        return false;
    }
    exe_path.contains(pattern)
}
