/*
 * File: lib.rs                                                                *
 * Path: libs\windows-features\src\lib.rs                                      *
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

//! A 100% safe, high-level Rust wrapper over the native Windows DISM API (`DismApi.dll`).
//!
//! Provides management for:
//! - **Windows Optional Features** (e.g. `Microsoft-Windows-Subsystem-Linux`, `NetFx3`, `Hyper-V`).
//! - **Windows Capabilities / Features on Demand** (e.g. `OpenSSH.Client`, `OpenSSH.Server`, `Browser.InternetExplorer`).
//!
//! All `unsafe` FFI calls, pointer manipulation, and dynamic library loading are fully
//! encapsulated within this crate. Consumer crates (`core`, `handlers`) remain clean and safe.

mod error;
mod ffi;
mod session;
mod types;

pub use error::{DismError, Result};
pub use session::{get_online_capabilities, get_online_features, DismSession};
pub use types::{Capability, CapabilityInfo, Feature, FeatureInfo, FeatureState};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dism_api_loading_and_elevation_check() {
        // When running tests in a non-elevated environment, attempting to open
        // an online DISM session should report DismError::ElevationRequired or succeed if elevated.
        // It must NOT crash, panic, or segfault.
        match DismSession::open_online() {
            Ok(session) => {
                let features = session.get_features();
                println!("Features result: {:?}", features.is_ok());
            }
            Err(DismError::ElevationRequired) => {
                // Expected when tests run without Administrator elevation (error 740 / 0x800702E4).
            }
            Err(DismError::AccessDenied) => {
                // Also acceptable when security policies restrict DISM.
            }
            Err(err) => {
                panic!("Inesperado error de DISM al probar sesión: {:?}", err);
            }
        }
    }
}

