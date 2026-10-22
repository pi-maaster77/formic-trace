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

