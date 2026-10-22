/*
 * File: snapshot.rs                                                           *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\domain\inspectors\system_features\snapshot.rs *
 * Project: system_features                                                    *
 * Author: pi-maaster77                                                        *
 * Created Date: Mo/10/2026 01:20:14                                           *
 * Last Modified: Thu Oct 22 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */


use std::collections::BTreeMap;
use tracing::info;
use windows_features::FeatureState;

/// Snapshot of the Windows Optional Features and Capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemFeaturesSnapshot {
    pub features: BTreeMap<String, FeatureState>,
    pub capabilities: BTreeMap<String, FeatureState>,
}

pub(super) fn log_snapshot(snapshot: &SystemFeaturesSnapshot) {
    let active_features = snapshot
        .features
        .values()
        .filter(|state| state.is_enabled_or_pending())
        .count();
    let active_capabilities = snapshot
        .capabilities
        .values()
        .filter(|state| state.is_enabled_or_pending())
        .count();

    info!(
        total_features = snapshot.features.len(),
        active_or_pending_features = active_features,
        total_capabilities = snapshot.capabilities.len(),
        active_or_pending_capabilities = active_capabilities,
        "Snapshot de características y capacidades de Windows capturado."
    );
}

