/*
 * File: session.rs                                                            *
 * Path: libs\windows-features\src\session.rs                                  *
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

use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};

use crate::error::{check_hresult, DismError, Result};
use crate::ffi::{
    to_wide, wide_to_string, DismSessionHandle, RawDismCapability, RawDismCapabilityInfo,
    RawDismFeature, RawDismFeatureInfo, RawDismModule, DISM_ONLINE_IMAGE,
};
use crate::types::{Capability, CapabilityInfo, Feature, FeatureInfo, FeatureState};

static GLOBAL_DISM_LIB: OnceLock<Mutex<Option<Arc<DismLibrary>>>> = OnceLock::new();

/// Internal wrapper holding the loaded DISM module and initialized state.
pub struct DismLibrary {
    module: RawDismModule,
}

impl DismLibrary {
    /// Loads the DISM library and initializes DISM API.
    pub fn new() -> Result<Arc<Self>> {
        let mutex = GLOBAL_DISM_LIB.get_or_init(|| Mutex::new(None));
        let mut guard = mutex.lock().map_err(|_| {
            DismError::SessionError("envenenamiento de lock al acceder a la librería DISM".into())
        })?;

        if let Some(existing) = guard.as_ref() {
            return Ok(Arc::clone(existing));
        }

        let module = RawDismModule::load()?;
        unsafe {
            eprintln!("[DISM-DIAG] DismInitialize enter");
            let hr = (module.vtable.initialize)(0, ptr::null(), ptr::null());
            eprintln!("[DISM-DIAG] DismInitialize returned {hr:#010x}");
            check_hresult(hr, "DismInitialize")?;
        }

        let lib = Arc::new(Self { module });
        *guard = Some(Arc::clone(&lib));
        Ok(lib)
    }
}

impl Drop for DismLibrary {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.module.vtable.shutdown)();
        }
    }
}

/// A safe RAII wrapper around an active DISM servicing session.
pub struct DismSession {
    handle: DismSessionHandle,
    lib: Arc<DismLibrary>,
}

impl DismSession {
    /// Opens a DISM session targeting the currently running Windows OS.
    pub fn open_online() -> Result<Self> {
        let lib = DismLibrary::new()?;
        let mut handle: DismSessionHandle = 0;
        let online_image_wide = to_wide(DISM_ONLINE_IMAGE);

        unsafe {
            eprintln!("[DISM-DIAG] DismOpenSession enter");
            let hr = (lib.module.vtable.open_session)(
                online_image_wide.as_ptr(),
                ptr::null(),
                ptr::null(),
                &mut handle,
            );
            eprintln!("[DISM-DIAG] DismOpenSession returned {hr:#010x}");
            check_hresult(hr, "DismOpenSession (Online)")?;
        }

        Ok(Self { handle, lib })
    }

    /// Opens a DISM session targeting an offline Windows image path.
    pub fn open_offline(image_path: &str) -> Result<Self> {
        let lib = DismLibrary::new()?;
        let mut handle: DismSessionHandle = 0;
        let image_wide = to_wide(image_path);

        unsafe {
            let hr = (lib.module.vtable.open_session)(
                image_wide.as_ptr(),
                ptr::null(),
                ptr::null(),
                &mut handle,
            );
            check_hresult(hr, &format!("DismOpenSession ({image_path})"))?;
        }

        Ok(Self { handle, lib })
    }

    /// Enumerates all Windows Optional Features in this session.
    pub fn get_features(&self) -> Result<Vec<Feature>> {
        let mut raw_features: *mut RawDismFeature = ptr::null_mut();
        let mut count: u32 = 0;

        unsafe {
            eprintln!("[DISM-DIAG] DismGetFeatures enter");
            let hr = (self.lib.module.vtable.get_features)(
                self.handle,
                ptr::null(),
                0,
                &mut raw_features,
                &mut count,
            );
            eprintln!(
                "[DISM-DIAG] DismGetFeatures returned {hr:#010x}, count={count}, ptr={raw_features:p}"
            );
            check_hresult(hr, "DismGetFeatures")?;

            if raw_features.is_null() || count == 0 {
                return Ok(Vec::new());
            }

            let slice = std::slice::from_raw_parts(raw_features, count as usize);
            let mut result = Vec::with_capacity(count as usize);

            for (index, item) in slice.iter().enumerate() {
                let name_ptr = ptr::addr_of!(item.feature_name).read_unaligned();
                let state_raw = ptr::addr_of!(item.state).read_unaligned();
                eprintln!(
                    "[DISM-DIAG] feature[{index}] name_ptr={name_ptr:p}, state={state_raw}"
                );
                let name = wide_to_string(name_ptr);
                eprintln!("[DISM-DIAG] feature[{index}] name decoded");
                result.push(Feature {
                    name,
                    state: FeatureState::from_u32(state_raw),
                });
            }

            eprintln!("[DISM-DIAG] DismDelete features enter");
            let _ = (self.lib.module.vtable.delete)(raw_features as *mut c_void);
            eprintln!("[DISM-DIAG] DismDelete features returned");
            Ok(result)
        }
    }

    /// Retrieves detailed metadata for a specific Windows Optional Feature.
    pub fn get_feature_info(&self, feature_name: &str) -> Result<FeatureInfo> {
        let name_wide = to_wide(feature_name);
        let mut raw_info: *mut RawDismFeatureInfo = ptr::null_mut();

        unsafe {
            let hr = (self.lib.module.vtable.get_feature_info)(
                self.handle,
                name_wide.as_ptr(),
                ptr::null(),
                0,
                &mut raw_info,
            );
            check_hresult(hr, &format!("DismGetFeatureInfo ({feature_name})"))?;

            if raw_info.is_null() {
                return Err(DismError::FeatureNotFound(feature_name.to_string()));
            }

            let info = &*raw_info;
            let name_ptr = ptr::addr_of!(info.feature_name).read_unaligned();
            let state_raw = ptr::addr_of!(info.feature_state).read_unaligned();
            let display_name_ptr = ptr::addr_of!(info.display_name).read_unaligned();
            let description_ptr = ptr::addr_of!(info.description).read_unaligned();

            let result = FeatureInfo {
                name: wide_to_string(name_ptr),
                state: FeatureState::from_u32(state_raw),
                display_name: wide_to_string(display_name_ptr),
                description: wide_to_string(description_ptr),
            };

            let _ = (self.lib.module.vtable.delete)(raw_info as *mut c_void);
            Ok(result)
        }
    }

    /// Enables a Windows Optional Feature.
    pub fn enable_feature(
        &self,
        feature_name: &str,
        enable_all_dependencies: bool,
    ) -> Result<()> {
        let name_wide = to_wide(feature_name);

        unsafe {
            eprintln!("[DISM-DIAG] DismEnableFeature enter: {feature_name}");
            let hr = (self.lib.module.vtable.enable_feature)(
                self.handle,
                name_wide.as_ptr(),
                ptr::null(),
                if enable_all_dependencies { 1 } else { 0 },
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            eprintln!("[DISM-DIAG] DismEnableFeature returned {hr:#010x}");
            check_hresult(hr, &format!("DismEnableFeature ({feature_name})"))
        }
    }

    /// Disables a Windows Optional Feature.
    pub fn disable_feature(&self, feature_name: &str, remove_payload: bool) -> Result<()> {
        let name_wide = to_wide(feature_name);

        unsafe {
            let hr = (self.lib.module.vtable.disable_feature)(
                self.handle,
                name_wide.as_ptr(),
                ptr::null(),
                if remove_payload { 1 } else { 0 },
                ptr::null_mut(),
                ptr::null_mut(),
            );
            check_hresult(hr, &format!("DismDisableFeature ({feature_name})"))
        }
    }

    /// Enumerates all Windows Capabilities (Features on Demand) in this session.
    pub fn get_capabilities(&self) -> Result<Vec<Capability>> {
        let mut raw_caps: *mut RawDismCapability = ptr::null_mut();
        let mut count: u32 = 0;

        unsafe {
            eprintln!("[DISM-DIAG] DismGetCapabilities enter");
            let hr =
                (self.lib.module.vtable.get_capabilities)(self.handle, &mut raw_caps, &mut count);
            eprintln!(
                "[DISM-DIAG] DismGetCapabilities returned {hr:#010x}, count={count}, ptr={raw_caps:p}"
            );
            check_hresult(hr, "DismGetCapabilities")?;

            if raw_caps.is_null() || count == 0 {
                return Ok(Vec::new());
            }

            let slice = std::slice::from_raw_parts(raw_caps, count as usize);
            let mut result = Vec::with_capacity(count as usize);

            for item in slice {
                let name_ptr = ptr::addr_of!(item.name).read_unaligned();
                let state_raw = ptr::addr_of!(item.state).read_unaligned();
                result.push(Capability {
                    name: wide_to_string(name_ptr),
                    state: FeatureState::from_u32(state_raw),
                });
            }

            let _ = (self.lib.module.vtable.delete)(raw_caps as *mut c_void);
            Ok(result)
        }
    }

    /// Retrieves detailed metadata for a specific Windows Capability.
    pub fn get_capability_info(&self, capability_name: &str) -> Result<CapabilityInfo> {
        let name_wide = to_wide(capability_name);
        let mut raw_info: *mut RawDismCapabilityInfo = ptr::null_mut();

        unsafe {
            let hr = (self.lib.module.vtable.get_capability_info)(
                self.handle,
                name_wide.as_ptr(),
                &mut raw_info,
            );
            check_hresult(hr, &format!("DismGetCapabilityInfo ({capability_name})"))?;

            if raw_info.is_null() {
                return Err(DismError::CapabilityNotFound(capability_name.to_string()));
            }

            let info = &*raw_info;
            let name_ptr = ptr::addr_of!(info.name).read_unaligned();
            let state_raw = ptr::addr_of!(info.state).read_unaligned();
            let display_name_ptr = ptr::addr_of!(info.display_name).read_unaligned();
            let description_ptr = ptr::addr_of!(info.description).read_unaligned();
            let download_size = ptr::addr_of!(info.download_size).read_unaligned();
            let install_size = ptr::addr_of!(info.install_size).read_unaligned();

            let result = CapabilityInfo {
                name: wide_to_string(name_ptr),
                state: FeatureState::from_u32(state_raw),
                display_name: wide_to_string(display_name_ptr),
                description: wide_to_string(description_ptr),
                download_size,
                install_size,
            };

            let _ = (self.lib.module.vtable.delete)(raw_info as *mut c_void);
            Ok(result)
        }
    }

    /// Adds / Installs a Windows Capability.
    pub fn add_capability(&self, capability_name: &str, limit_access: bool) -> Result<()> {
        let name_wide = to_wide(capability_name);

        unsafe {
            let hr = (self.lib.module.vtable.add_capability)(
                self.handle,
                name_wide.as_ptr(),
                if limit_access { 1 } else { 0 },
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            check_hresult(hr, &format!("DismAddCapability ({capability_name})"))
        }
    }

    /// Removes / Uninstalls a Windows Capability.
    pub fn remove_capability(&self, capability_name: &str) -> Result<()> {
        let name_wide = to_wide(capability_name);

        unsafe {
            let hr = (self.lib.module.vtable.remove_capability)(
                self.handle,
                name_wide.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            check_hresult(hr, &format!("DismRemoveCapability ({capability_name})"))
        }
    }
}

impl Drop for DismSession {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.lib.module.vtable.close_session)(self.handle);
        }
    }
}

/// Concurrently safe shortcut to query all online Windows Optional Features.
pub fn get_online_features() -> Result<Vec<Feature>> {
    let session = DismSession::open_online()?;
    session.get_features()
}

/// Concurrently safe shortcut to query all online Windows Capabilities.
pub fn get_online_capabilities() -> Result<Vec<Capability>> {
    let session = DismSession::open_online()?;
    session.get_capabilities()
}

