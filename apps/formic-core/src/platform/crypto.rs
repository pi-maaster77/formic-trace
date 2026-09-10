use std::path::Path;

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{HANDLE, HWND};
#[cfg(target_os = "windows")]
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_DATA, WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_STATE_ACTION,
    WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_UI_NONE,
    WINTRUST_ACTION_GENERIC_VERIFY_V2,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid,
    Unsigned,
    Untrusted,
    Revoked,
    UnknownFailure(i32),
}

#[cfg(target_os = "windows")]
pub fn verify_binary(path: &Path) -> SignatureStatus {
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