/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/platform/fs_monitor.rs
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

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::mpsc::Sender;
use std::thread;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED,
    FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME, FILE_ACTION_RENAMED_OLD_NAME,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

use crate::shared::models::{FileAction, FileEvent};

pub struct FileMonitor {
    handle: HANDLE,
}

pub type DirectoryMonitor = FileMonitor;

impl FileMonitor {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let path_utf16: Vec<u16> = path_ref
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let handle = CreateFileW(
                path_utf16.as_ptr(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                0,
            );

            if handle == INVALID_HANDLE_VALUE {
                let err_code = GetLastError();
                return Err(format!(
                    "No se pudo abrir el directorio para monitoreo en '{}' (Win32 Error Code: {})",
                    path_ref.display(),
                    err_code
                ));
            }

            Ok(Self { handle })
        }
    }

    pub fn start_worker(self, tx: Sender<FileEvent>) -> thread::JoinHandle<()> {
        thread::spawn(move || loop {
            if let Err(_e) = self.read_changes(&tx) {
                break;
            }
        })
    }

    pub fn read_changes(&self, tx: &Sender<FileEvent>) -> Result<(), String> {
        let mut buffer = [0u8; 1024];
        let mut bytes_returned = 0u32;

        let filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE;

        unsafe {
            let success = ReadDirectoryChangesW(
                self.handle,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                1, // watch_subtree = TRUE
                filter,
                &mut bytes_returned,
                null_mut(),
                None,
            );

            if success == 0 {
                let err_code = GetLastError();
                return Err(format!(
                    "Error al leer cambios en el directorio (Win32 Error Code: {})",
                    err_code
                ));
            }

            let mut offset = 0usize;
            loop {
                let info = &*(buffer.as_ptr().add(offset) as *const FILE_NOTIFY_INFORMATION);

                let name_len = (info.FileNameLength / 2) as usize;
                let name_slice = std::slice::from_raw_parts(info.FileName.as_ptr(), name_len);
                let path = PathBuf::from(String::from_utf16_lossy(name_slice));

                let action = match info.Action {
                    FILE_ACTION_ADDED => Some(FileAction::Created),
                    FILE_ACTION_REMOVED => Some(FileAction::Deleted),
                    FILE_ACTION_MODIFIED => Some(FileAction::Modified),
                    FILE_ACTION_RENAMED_OLD_NAME | FILE_ACTION_RENAMED_NEW_NAME => {
                        Some(FileAction::Renamed)
                    }
                    _ => None,
                };

                if let Some(action) = action {
                    let event = FileEvent { path, action };
                    if tx.send(event).is_err() {
                        return Err("Canal de eventos cerrado".to_string());
                    }
                }

                if info.NextEntryOffset == 0 {
                    break;
                }
                offset += info.NextEntryOffset as usize;
            }
        }

        Ok(())
    }
}

impl Drop for FileMonitor {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE && self.handle != 0 {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}
