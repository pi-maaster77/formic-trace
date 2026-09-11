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
 
use crate::config::{FormicConfig, Rule, SignatureStatusRequirement};
use crate::shared::models::{PolicyDecision, SignatureStatus, SystemEvent};
use glob_match::glob_match;
use std::path::Path;

fn normalize_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('/', "\\").to_lowercase();

    if raw.starts_with(r"\device\harddiskvolume") {
        if let Some(idx) = raw[21..].find('\\') {
            let rest = &raw[21 + idx..];
            return format!("c:{}", rest);
        }
    }

    raw
}

fn matches_signature(req: &SignatureStatusRequirement, status: &SignatureStatus) -> bool {
    match req {
        SignatureStatusRequirement::Any => true,
        SignatureStatusRequirement::Signed => matches!(status, SignatureStatus::SignedValid),
        SignatureStatusRequirement::Unsigned => matches!(
            status,
            SignatureStatus::Unsigned | SignatureStatus::Untrusted | SignatureStatus::Revoked
        ),
        SignatureStatusRequirement::UntrustedRoot => matches!(status, SignatureStatus::Untrusted),
        SignatureStatusRequirement::Expired => matches!(status, SignatureStatus::Revoked),
    }
}

fn matches_path_pattern(path: &str, pattern: Option<&str>) -> bool {
    let Some(pattern) = pattern else {
        return true;
    };

    let normalized_pattern = pattern.replace('/', "\\").to_lowercase();

    if normalized_pattern == "*" || normalized_pattern.is_empty() {
        return true;
    }

    if normalized_pattern.contains('*') || normalized_pattern.contains('?') {
        glob_match(&normalized_pattern, path)
    } else {
        path.contains(&normalized_pattern)
    }
}

fn matches_rule(rule: &Rule, path: &str, sig_status: Option<&SignatureStatus>) -> bool {
    // 1. Validar patrón de ruta
    if !matches_path_pattern(path, rule.path_pattern.as_deref()) {
        return false;
    }

    // 2. Validar firma digital
    if let Some(status) = sig_status {
        // Si el estado es firma válida y la regla busca firmas dudosas o sin firmar, DESCARTAR
        if *status == SignatureStatus::SignedValid
            && rule.signature_status != SignatureStatusRequirement::Signed
            && rule.signature_status != SignatureStatusRequirement::Any
        {
            return false;
        }

        if !matches_signature(&rule.signature_status, status) {
            return false;
        }
    }

    true
}

pub fn evaluate<'a>(event: &'a SystemEvent, config: &'a FormicConfig) -> PolicyDecision<'a> {
    match event {
        SystemEvent::File(file_event) => {
            let normalized_path = normalize_path(&file_event.path);
            for rule in &config.rules {
                if matches_rule(rule, &normalized_path, None) {
                    return PolicyDecision {
                        action: rule.action.clone(),
                        matched_rule: Some(&rule.name),
                    };
                }
            }
        }
        SystemEvent::Process(proc_event) => {
            let normalized_exe = normalize_path(&proc_event.path);
            for rule in &config.rules {
                if matches_rule(rule, &normalized_exe, Some(&proc_event.signature_status)) {
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