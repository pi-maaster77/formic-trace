/*
 * Formic Trace - Declarative Application Whitelisting for Windows
 * File: /apps/formic-core/src/platform/crypto.rs
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

use std::path::Path;

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
#[cfg(target_os = "windows")]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_STATE_ACTION, WINTRUST_DATA_UICONTEXT,
    WINTRUST_FILE_INFO, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_UI_NONE,
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid,
    SystemProtected,
    Unsigned,
    Untrusted,
    Revoked,
    UnknownFailure(i32),
}

#[cfg(target_os = "windows")]
pub fn verify_binary(path: &Path) -> SignatureStatus {
    let path_str = path.to_string_lossy();
    if path_str.is_empty() || path_str == "System" || path_str == "System Idle Process" {
        return SignatureStatus::SystemProtected;
    }

    if !path.exists() {
        return SignatureStatus::Unsigned;
    }

    let embedded_status = verify_embedded_signature(path);
    if embedded_status == SignatureStatus::Valid {
        return SignatureStatus::Valid;
    }

    match verify_catalog_signature(path) {
        SignatureStatus::Valid => SignatureStatus::Valid,
        _ => embedded_status,
    }
}

#[cfg(target_os = "windows")]
fn verify_embedded_signature(path: &Path) -> SignatureStatus {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide_path.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WINTRUST_DATA_STATE_ACTION(0),
        hWVTStateData: HANDLE::default(),
        pwszURLReference: windows::core::PWSTR::null(),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action_guid,
            &mut trust_data as *mut _ as *mut _,
        )
    };

    parse_wintrust_status(status)
}

#[cfg(target_os = "windows")]
fn verify_catalog_signature(path: &Path) -> SignatureStatus {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let h_file = CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                FILE_GENERIC_READ.0, // .0 convierte el newtype struct/enum al u32 subyacente que espera dwDesiredAccess
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                Default::default(),
                HANDLE::default(),
            );

        if h_file.is_err() || h_file.as_ref().unwrap().is_invalid() {
            return SignatureStatus::Unsigned;
        }

        let file_handle = h_file.unwrap();
        let mut cat_admin: isize = 0;

        if CryptCATAdminAcquireContext2(&mut cat_admin, None, PCWSTR::null(), None, 0).is_err() {
            let _ = CloseHandle(file_handle);
            return SignatureStatus::Unsigned;
        }

        let mut hash_size: u32 = 0;
        let _ = CryptCATAdminCalcHashFromFileHandle2(cat_admin, file_handle, &mut hash_size, None, 0);

        if hash_size == 0 {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            let _ = CloseHandle(file_handle);
            return SignatureStatus::Unsigned;
        }

        let mut hash_buf = vec![0u8; hash_size as usize];
        if CryptCATAdminCalcHashFromFileHandle2(
            cat_admin,
            file_handle,
            &mut hash_size,
            Some(hash_buf.as_mut_ptr()),
            0,
        )
        .is_err()
        {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            let _ = CloseHandle(file_handle);
            return SignatureStatus::Unsigned;
        }

        let cat_info_handle: isize = CryptCATAdminEnumCatalogFromHash(cat_admin, &hash_buf, 0, None);
        if cat_info_handle == 0 {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            let _ = CloseHandle(file_handle);
            return SignatureStatus::Unsigned;
        }

        let mut cat_info = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };

        let result = if CryptCATCatalogInfoFromContext(cat_info_handle, &mut cat_info, 0).is_ok() {
            let tag_wide: Vec<u16> = hash_buf
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut cat_trust_info = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                dwCatalogVersion: 0,
                pcwszCatalogFilePath: PCWSTR(cat_info.wszCatalogFile.as_ptr()),
                pcwszMemberFilePath: PCWSTR(wide_path.as_ptr()),
                pcwszMemberTag: PCWSTR(tag_wide.as_ptr()),
                hMemberFile: file_handle,
                pbCalculatedFileHash: hash_buf.as_mut_ptr(),
                cbCalculatedFileHash: hash_size,
                pcCatalogContext: std::ptr::null_mut(),
                hCatAdmin: cat_admin,
            };

            let mut trust_data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: std::ptr::null_mut(),
                pSIPClientData: std::ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_CATALOG,
                Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                    pCatalog: &mut cat_trust_info,
                },
                dwStateAction: WINTRUST_DATA_STATE_ACTION(0),
                hWVTStateData: HANDLE::default(),
                pwszURLReference: windows::core::PWSTR::null(),
                dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
                dwUIContext: WINTRUST_DATA_UICONTEXT(0),
                pSignatureSettings: std::ptr::null_mut(),
            };

            let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let status = WinVerifyTrust(
                HWND::default(),
                &mut action_guid,
                &mut trust_data as *mut _ as *mut _,
            );
            parse_wintrust_status(status)
        } else {
            SignatureStatus::Unsigned
        };

        let _ = CryptCATAdminReleaseCatalogContext(cat_admin, cat_info_handle, 0);
        let _ = CryptCATAdminReleaseContext(cat_admin, 0);
        let _ = CloseHandle(file_handle);

        result
    }
}

#[cfg(target_os = "windows")]
fn parse_wintrust_status(status: i32) -> SignatureStatus {
    match status {
        0 => SignatureStatus::Valid,
        -2146762496 => SignatureStatus::Unsigned,
        -2146762487 => SignatureStatus::Untrusted,
        -2146762484 => SignatureStatus::Revoked,
        code => SignatureStatus::UnknownFailure(code),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn verify_binary(_path: &Path) -> SignatureStatus {
    SignatureStatus::Valid
}
