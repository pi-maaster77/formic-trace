/*
 * Formic Trace - Declarative Application Whitelisting for Windows
 * File: /apps/formic-core/src/platform/process_monitor.rs
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

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::thread;
use sysinfo::{ProcessRefreshKind, System};

use crate::config::ProcessConfig;
use crate::platform::crypto::verify_binary;
use crate::shared::models::{ProcessAction, ProcessEvent, SignatureStatus, SystemEvent};

use std::os::windows::ffi::OsStrExt;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

pub struct ProcessMonitor;

fn normalize_nt_path(path: PathBuf) -> PathBuf {
    let path_str = path.to_string_lossy();
    if !path_str.starts_with(r"\Device\") {
        return path;
    }

    // Iterar unidades de disco de A: a Z: para resolver la ruta NT
    for drive in (b'A'..=b'Z').map(|c| format!("{}:", c as char)) {
        let mut drive_utf16: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut target_path = vec![0u16; 512];
        
        let len = unsafe {
            QueryDosDeviceW(
                windows::core::PCWSTR(drive_utf16.as_ptr()),
                Some(&mut target_path),
            )
        };

        if len > 0 {
            let target = String::from_utf16_lossy(&target_path[..len as usize - 2]);
            if path_str.starts_with(&target) {
                let relative = &path_str[target.len()..];
                return PathBuf::from(format!("{}{}", drive, relative));
            }
        }
    }

    path
}

impl ProcessMonitor {
    pub fn start(config: &ProcessConfig, tx: Sender<SystemEvent>) -> thread::JoinHandle<()> {
        let interval = config.poll_interval();
        let track_cmdline = config.track_cmdline;
        let alert_unsigned_only = config.alert_on_unsigned_only;

        thread::spawn(move || {
            let mut sys = System::new();
            let mut known_pids = HashSet::new();

            loop {
                sys.refresh_processes_specifics(ProcessRefreshKind::everything());
                
                // Evitamos allocations innecesarias en cada iteración capturando directamente los PIDs
                let current_pids: HashSet<_> = sys.processes().keys().copied().collect();

                for pid in current_pids.difference(&known_pids) {
                    let pid_u32 = pid.as_u32();

                    let proc_ = match sys.process(*pid) {
                        Some(p) => p,
                        None => continue, // El proceso finalizó antes de poder inspeccionarlo
                    };

                    // Manejo adecuado de pseudo-procesos del kernel de Windows
                    let raw_path = match pid_u32 {
                        0 => PathBuf::from("System Idle Process"),
                        4 => PathBuf::from("System"),
                        _ => match proc_.exe() {
                            Some(p) => p.to_path_buf(),
                            None => PathBuf::default(), // Proceso zombie o sin permisos de lectura en la ruta
                        },
                    };
                    let path = normalize_nt_path(raw_path);
                    
                    // Si la ruta está vacía o es un proceso del kernel, omitimos la verificación crypto
                    let sig_status = if pid_u32 == 0 || pid_u32 == 4 || path.as_os_str().is_empty() {
                        SignatureStatus::SystemProtected
                    } else {
                        // Convertimos de crypto::SignatureStatus a shared::models::SignatureStatus
                        match verify_binary(&path) {
                            crate::platform::crypto::SignatureStatus::Valid => SignatureStatus::SignedValid,
                            crate::platform::crypto::SignatureStatus::SystemProtected => SignatureStatus::SystemProtected,
                            crate::platform::crypto::SignatureStatus::Unsigned => SignatureStatus::Unsigned,
                            crate::platform::crypto::SignatureStatus::Untrusted => SignatureStatus::Untrusted,
                            crate::platform::crypto::SignatureStatus::Revoked => SignatureStatus::Revoked,
                            crate::platform::crypto::SignatureStatus::UnknownFailure(_) => SignatureStatus::Unsigned,
                        }
                    };

                    // Filtrado temprano según la configuración del monitor
                    if alert_unsigned_only && sig_status == SignatureStatus::SignedValid {
                        continue;
                    }

                    let command_line = if track_cmdline {
                        proc_.cmd().join(" ")
                    } else {
                        String::new()
                    };

                    let proc_event = ProcessEvent {
                        pid: pid_u32,
                        ppid: proc_.parent().map(|p| p.as_u32()).unwrap_or(0),
                        path,
                        command_line,
                        action: ProcessAction::Spawned,
                        signature_status: sig_status,
                    };

                    if tx.send(SystemEvent::Process(proc_event)).is_err() {
                        // El canal receptor se cerró (el servicio principal se está deteniendo)
                        return;
                    }
                }

                known_pids = current_pids;
                thread::sleep(interval);
            }
        })
    }
}
