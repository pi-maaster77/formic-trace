/*
 * File: error.rs                                                              *
 * Path: libs\windows-features\src\error.rs                                    *
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

use thiserror::Error;

/// Errors returned when interacting with the Windows DISM API.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum DismError {
    /// Failed to dynamically load DismApi.dll from the system.
    #[error("no se pudo cargar la librería DismApi.dll: {0}")]
    DllLoadFailed(String),

    /// A required DISM function symbol was not found in DismApi.dll.
    #[error("símbolo de función no encontrado en DismApi.dll: {0}")]
    SymbolNotFound(&'static str),

    /// The operation requires Windows Administrator elevation.
    #[error("la operación requiere privilegios de Administrador (elevación UAC / código 740)")]
    ElevationRequired,

    /// Access was denied.
    #[error("acceso denegado al interactuar con la API DISM")]
    AccessDenied,

    /// The operation completed successfully, but requires a system reboot to take full effect.
    #[error("la operación se completó correctamente pero requiere reiniciar el sistema")]
    RebootRequired,

    /// The requested Windows feature was not found.
    #[error("característica opcional de Windows no encontrada: '{0}'")]
    FeatureNotFound(String),

    /// The requested Windows capability was not found.
    #[error("capacidad de Windows (Feature on Demand) no encontrada: '{0}'")]
    CapabilityNotFound(String),

    /// The DISM API returned a failure HRESULT code.
    #[error("error de la API DISM (HRESULT 0x{code:08X}): {message}")]
    Hresult {
        code: i32,
        message: String,
    },

    /// An input string contained invalid null bytes or failed wide character conversion.
    #[error("cadena de texto con formato de caracteres anchos (UTF-16) inválido")]
    InvalidWideString,

    /// Internal session error.
    #[error("error en la sesión DISM: {0}")]
    SessionError(String),
}

pub type Result<T> = std::result::Result<T, DismError>;

pub(crate) fn check_hresult(hr: i32, context: &str) -> Result<()> {
    match hr as u32 {
        0 => Ok(()), // S_OK
        0x00000BC2 | 0x80070BC2 => Err(DismError::RebootRequired), // ERROR_SUCCESS_REBOOT_REQUIRED (3010)
        0x00000669 | 0x80070669 => Err(DismError::RebootRequired), // ERROR_SUCCESS_REBOOT_INITIATED (1641)
        0x800702E4 => Err(DismError::ElevationRequired),          // ERROR_ELEVATION_REQUIRED (740)
        0x80070005 => Err(DismError::AccessDenied),              // E_ACCESSDENIED (5)
        0x80070002 => Err(DismError::Hresult {
            code: hr,
            message: format!("{context}: no se encontró el elemento especificado"),
        }),
        code => Err(DismError::Hresult {
            code: hr,
            message: format!("{context} falló con HRESULT 0x{code:08X}"),
        }),
    }
}

