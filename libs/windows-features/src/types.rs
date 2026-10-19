/*
 * File: types.rs                                                              *
 * Path: libs\windows-features\src\types.rs                                    *
 * Project: windows-features                                                   *
 * Author: pi-maaster77                                                        *
 * Created Date: Su/10/2026                                                    *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use serde::{Deserialize, Serialize};

/// Installation state of a Windows Feature or Capability according to the DISM API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureState {
    /// Not present in the image and no payload is staged.
    NotPresent,
    /// Pending uninstallation.
    UninstallPending,
    /// Staged in the component store but not active.
    Staged,
    /// Resolved.
    Resolved,
    /// Pending action.
    Pending,
    /// Fully installed and active.
    Installed,
    /// Installation is pending (requires reboot or download).
    InstallPending,
    /// Superseded by a newer package or component.
    Superseded,
    /// Partially installed.
    PartiallyInstalled,
    /// Other state code returned by DISM.
    Unknown(u32),
}

impl FeatureState {
    /// Returns true if the component is fully installed and active.
    pub fn is_installed(&self) -> bool {
        matches!(self, Self::Installed)
    }

    /// Returns true if the component is active or currently being installed.
    pub fn is_enabled_or_pending(&self) -> bool {
        matches!(self, Self::Installed | Self::InstallPending)
    }

    /// Converts from raw DISM C enum value (`DismPackageFeatureState`).
    pub fn from_u32(raw: u32) -> Self {
        match raw {
            0 => Self::NotPresent,
            1 => Self::UninstallPending,
            2 => Self::Staged,
            3 => Self::Resolved,
            4 => Self::Pending,
            5 => Self::Installed,
            6 => Self::InstallPending,
            7 => Self::Superseded,
            8 => Self::PartiallyInstalled,
            other => Self::Unknown(other),
        }
    }

    /// Returns the raw DISM C enum integer value.
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::NotPresent => 0,
            Self::UninstallPending => 1,
            Self::Staged => 2,
            Self::Resolved => 3,
            Self::Pending => 4,
            Self::Installed => 5,
            Self::InstallPending => 6,
            Self::Superseded => 7,
            Self::PartiallyInstalled => 8,
            Self::Unknown(val) => *val,
        }
    }
}

/// A Windows Optional Feature (e.g., `Microsoft-Windows-Subsystem-Linux`, `NetFx3`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Feature {
    /// Internal programmatic name (e.g., `"Microsoft-Windows-Subsystem-Linux"`).
    pub name: String,
    /// Current installation state.
    pub state: FeatureState,
}

/// Detailed information about a Windows Optional Feature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureInfo {
    /// Internal programmatic name.
    pub name: String,
    /// Current installation state.
    pub state: FeatureState,
    /// Human-friendly display name.
    pub display_name: String,
    /// Detailed description of the feature.
    pub description: String,
}

/// A Windows Capability / Feature on Demand (e.g., `OpenSSH.Client~~~~0.0.1.0`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Capability {
    /// Internal programmatic name (e.g., `"OpenSSH.Client~~~~0.0.1.0"`).
    pub name: String,
    /// Current installation state.
    pub state: FeatureState,
}

/// Detailed information about a Windows Capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityInfo {
    /// Internal programmatic name.
    pub name: String,
    /// Current installation state.
    pub state: FeatureState,
    /// Human-friendly display name.
    pub display_name: String,
    /// Detailed description of the capability.
    pub description: String,
    /// Download size in bytes.
    pub download_size: u32,
    /// Disk space required once installed in bytes.
    pub install_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_state_conversions() {
        assert_eq!(FeatureState::from_u32(0), FeatureState::NotPresent);
        assert_eq!(FeatureState::from_u32(5), FeatureState::Installed);
        assert_eq!(FeatureState::from_u32(6), FeatureState::InstallPending);
        assert_eq!(FeatureState::from_u32(99), FeatureState::Unknown(99));

        assert!(FeatureState::Installed.is_installed());
        assert!(!FeatureState::NotPresent.is_installed());
        assert!(FeatureState::InstallPending.is_enabled_or_pending());
    }
}

