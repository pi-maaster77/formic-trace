/*
 * File: ffi.rs                                                                *
 * Path: libs\windows-features\src\ffi.rs                                      *
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

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(lpLibFileName: *const u16) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    fn FreeLibrary(hLibModule: *mut c_void) -> i32;
}

use crate::error::{DismError, Result};

pub const DISM_ONLINE_IMAGE: &str = "DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}";

pub type DismSessionHandle = u32;

#[repr(C, packed(4))]
pub struct RawDismFeature {
    pub feature_name: *const u16,
    pub state: u32,
}

#[repr(C, packed(4))]
pub struct RawDismFeatureInfo {
    pub feature_name: *const u16,
    pub feature_state: u32,
    pub display_name: *const u16,
    pub description: *const u16,
    pub restart_required: u32,
    pub custom_property: *mut c_void,
    pub custom_property_count: u32,
}

#[repr(C, packed(4))]
pub struct RawDismCapability {
    pub name: *const u16,
    pub state: u32,
}

#[repr(C, packed(4))]
pub struct RawDismCapabilityInfo {
    pub name: *const u16,
    pub state: u32,
    pub display_name: *const u16,
    pub description: *const u16,
    pub download_size: u32,
    pub install_size: u32,
}

pub type DismInitializeFn = unsafe extern "system" fn(
    log_level: u32,
    log_file_path: *const u16,
    scratch_directory: *const u16,
) -> i32;

pub type DismShutdownFn = unsafe extern "system" fn() -> i32;

pub type DismOpenSessionFn = unsafe extern "system" fn(
    image_path: *const u16,
    windows_directory: *const u16,
    system_drive: *const u16,
    session: *mut DismSessionHandle,
) -> i32;

pub type DismCloseSessionFn = unsafe extern "system" fn(session: DismSessionHandle) -> i32;

pub type DismGetFeaturesFn = unsafe extern "system" fn(
    session: DismSessionHandle,
    package_name: *const u16,
    package_identifier: u32,
    feature: *mut *mut RawDismFeature,
    count: *mut u32,
) -> i32;

pub type DismGetFeatureInfoFn = unsafe extern "system" fn(
    session: DismSessionHandle,
    feature_name: *const u16,
    package_name: *const u16,
    package_identifier: u32,
    feature_info: *mut *mut RawDismFeatureInfo,
) -> i32;

pub type DismEnableFeatureFn = unsafe extern "system" fn(
    session: DismSessionHandle,
    feature_name: *const u16,
    package_name: *const u16,
    enable_all: i32,
    limit_access: i32,
    source_paths: *const *const u16,
    source_path_count: u32,
    progress: *mut c_void,
    user_data: *mut c_void,
) -> i32;

pub type DismDisableFeatureFn = unsafe extern "system" fn(
    session: DismSessionHandle,
    feature_name: *const u16,
    package_name: *const u16,
    remove_payload: i32,
    progress: *mut c_void,
    user_data: *mut c_void,
) -> i32;

pub type DismGetCapabilitiesFn = unsafe extern "system" fn(
    session: DismSessionHandle,
    capability: *mut *mut RawDismCapability,
    count: *mut u32,
) -> i32;

pub type DismGetCapabilityInfoFn = unsafe extern "system" fn(
    session: DismSessionHandle,
    name: *const u16,
    info: *mut *mut RawDismCapabilityInfo,
) -> i32;

pub type DismAddCapabilityFn = unsafe extern "system" fn(
    session: DismSessionHandle,
    name: *const u16,
    limit_access: i32,
    source_paths: *const *const u16,
    source_path_count: u32,
    progress: *mut c_void,
    user_data: *mut c_void,
) -> i32;

pub type DismRemoveCapabilityFn = unsafe extern "system" fn(
    session: DismSessionHandle,
    name: *const u16,
    progress: *mut c_void,
    user_data: *mut c_void,
) -> i32;

pub type DismDeleteFn = unsafe extern "system" fn(dism_structure: *mut c_void) -> i32;

pub struct DismVtable {
    pub initialize: DismInitializeFn,
    pub shutdown: DismShutdownFn,
    pub open_session: DismOpenSessionFn,
    pub close_session: DismCloseSessionFn,
    pub get_features: DismGetFeaturesFn,
    pub get_feature_info: DismGetFeatureInfoFn,
    pub enable_feature: DismEnableFeatureFn,
    pub disable_feature: DismDisableFeatureFn,
    pub get_capabilities: DismGetCapabilitiesFn,
    pub get_capability_info: DismGetCapabilityInfoFn,
    pub add_capability: DismAddCapabilityFn,
    pub remove_capability: DismRemoveCapabilityFn,
    pub delete: DismDeleteFn,
}

pub struct RawDismModule {
    handle: *mut c_void,
    pub vtable: DismVtable,
}

impl RawDismModule {
    pub fn load() -> Result<Self> {
        unsafe {
            let wide_dll = to_wide("DismApi.dll");
            let handle = LoadLibraryW(wide_dll.as_ptr());
            if handle.is_null() {
                return Err(DismError::DllLoadFailed(
                    "No se pudo cargar DismApi.dll desde el sistema operativo".to_string(),
                ));
            }

            macro_rules! resolve_sym {
                ($fn_type:ty, $name:expr) => {{
                    let sym = GetProcAddress(handle, concat!($name, "\0").as_ptr());
                    if sym.is_null() {
                        FreeLibrary(handle);
                        return Err(DismError::SymbolNotFound($name));
                    }
                    std::mem::transmute::<*mut c_void, $fn_type>(sym)
                }};
            }

            let vtable = DismVtable {
                initialize: resolve_sym!(DismInitializeFn, "DismInitialize"),
                shutdown: resolve_sym!(DismShutdownFn, "DismShutdown"),
                open_session: resolve_sym!(DismOpenSessionFn, "DismOpenSession"),
                close_session: resolve_sym!(DismCloseSessionFn, "DismCloseSession"),
                get_features: resolve_sym!(DismGetFeaturesFn, "DismGetFeatures"),
                get_feature_info: resolve_sym!(DismGetFeatureInfoFn, "DismGetFeatureInfo"),
                enable_feature: resolve_sym!(DismEnableFeatureFn, "DismEnableFeature"),
                disable_feature: resolve_sym!(DismDisableFeatureFn, "DismDisableFeature"),
                get_capabilities: resolve_sym!(DismGetCapabilitiesFn, "DismGetCapabilities"),
                get_capability_info: resolve_sym!(DismGetCapabilityInfoFn, "DismGetCapabilityInfo"),
                add_capability: resolve_sym!(DismAddCapabilityFn, "DismAddCapability"),
                remove_capability: resolve_sym!(DismRemoveCapabilityFn, "DismRemoveCapability"),
                delete: resolve_sym!(DismDeleteFn, "DismDelete"),
            };

            Ok(Self { handle, vtable })
        }
    }
}

impl Drop for RawDismModule {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                FreeLibrary(self.handle);
            }
        }
    }
}

unsafe impl Send for RawDismModule {}
unsafe impl Sync for RawDismModule {}

pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub unsafe fn wide_to_string(p: *const u16) -> String {
    if p.is_null() || (p as usize) % std::mem::align_of::<u16>() != 0 {
        return String::new();
    }
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(p, len);
    String::from_utf16_lossy(slice)
}

#[cfg(all(test, target_pointer_width = "64"))]
mod tests {
    use super::{RawDismCapability, RawDismCapabilityInfo, RawDismFeature, RawDismFeatureInfo};

    #[test]
    fn dism_structures_use_four_byte_packing() {
        assert_eq!(std::mem::size_of::<RawDismFeature>(), 12);
        assert_eq!(std::mem::size_of::<RawDismFeatureInfo>(), 44);
        assert_eq!(std::mem::size_of::<RawDismCapability>(), 12);
        assert_eq!(std::mem::size_of::<RawDismCapabilityInfo>(), 36);
    }
}
