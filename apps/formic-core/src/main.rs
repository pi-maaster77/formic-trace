/*
 * Formic Trace - Declarative Application Whitelisting for Windows
 * File: /apps/formic-core/src/main.rs
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

mod cli;
mod config;
mod engine;
mod logger;
mod notifier;
mod platform;
mod shared;

use std::env;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use config::load_config;
use logger::{LogLevel, Logger};
use platform::crypto::SignatureStatus;
use shared::models::RuleAction;
use crate::shared::models::SystemEvent;

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, SE_PRIVILEGE_ENABLED, TOKEN_QUERY,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[cfg(target_os = "windows")]
fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token_handle = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        ).is_err() {
            return false;
        }

        let mut luid = LUID::default();
        let privilege_name: Vec<u16> = "SeDebugPrivilege".encode_utf16().chain(std::iter::once(0)).collect();

        if LookupPrivilegeValueW(None, windows::core::PCWSTR(privilege_name.as_ptr()), &mut luid).is_err() {
            let _ = CloseHandle(token_handle);
            return false;
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let res = AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&mut tp),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        );

        let _ = CloseHandle(token_handle);
        res.is_ok()
    }
}

#[cfg(not(target_os = "windows"))]
fn enable_debug_privilege() -> bool {
    true
}

fn resolve_watch_dir(configured_path: Option<&str>) -> PathBuf {
    if let Some(path_str) = configured_path {
        let p = PathBuf::from(path_str);
        if p.exists() {
            return p;
        }
    }

    if let Ok(user_profile) = env::var("USERPROFILE") {
        let user_temp = PathBuf::from(user_profile).join(r"AppData\Local\Temp");
        if user_temp.exists() {
            return user_temp;
        }
    }

    if let Ok(temp_env) = env::var("TEMP") {
        let temp_path = PathBuf::from(temp_env);
        if temp_path.exists() {
            return temp_path;
        }
    }

    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let logger = Logger::new(Some("formic.log"));
    logger.log(LogLevel::Info, "Inicializando Formic Core Daemon...");

    if enable_debug_privilege() {
        logger.log(LogLevel::Info, "Privilegio SeDebugPrivilege adquirido correctamente.");
    } else {
        logger.log(
            LogLevel::Warn,
            "No se pudo adquirir SeDebugPrivilege. Es posible que algunos procesos no puedan inspeccionarse.",
        );
    }

    let config_path = Path::new("config/formic.ncl");
    let config = load_config(config_path)?;

    logger.log(
        LogLevel::Info,
        &format!("Configuración cargada exitosamente desde {}", config_path.display()),
    );

    let (tx, rx) = mpsc::channel::<SystemEvent>();

    let _fs_monitor = platform::fs_monitor::FileMonitor::start(&config, tx.clone());
    let _proc_monitor = platform::process_monitor::ProcessMonitor::start(&config.process, tx.clone());
    let _reg_monitor = platform::registry_monitor::RegistryMonitor::start_watch(&config.registry, tx.clone());
    let _net_monitor = platform::net_monitor::NetMonitor::start_watch(&config.net, tx.clone());

    logger.log(LogLevel::Info, "Servicio de monitoreo iniciado. Escuchando eventos...");

    for event in rx {
        let event_info = match &event {
            SystemEvent::File(e) => format!("FS: {:?} | Acción: {:?}", e.path, e.action),
            SystemEvent::Process(e) => {
                let status = platform::crypto::verify_binary(&e.path);
                let status_str = match status {
                    SignatureStatus::Valid => "VALID_SIGNATURE".to_string(),
                    SignatureStatus::SystemProtected => "SYSTEM_PROTECTED".to_string(),
                    SignatureStatus::Unsigned => "UNSIGNED".to_string(),
                    SignatureStatus::Untrusted => "UNTRUSTED_ROOT".to_string(),
                    SignatureStatus::Revoked => "REVOKED".to_string(),
                    SignatureStatus::UnknownFailure(code) => format!("FAIL_CODE_{}", code),
                };

                format!("PROC: {:?} (PID: {}) | Status: {}", e.path, e.pid, status_str)
            }
            SystemEvent::Registry(e) => format!("REG: {:?}", e.key_path),
            SystemEvent::Net(e) => format!("NET: {}:{}", e.remote_addr, e.remote_port),
        };

        let decision = engine::evaluator::evaluate(&event, &config);
        let rule_name = decision.matched_rule.unwrap_or("DefaultPolicy");

        match decision.action {
            RuleAction::Allow => {
                logger.log(LogLevel::Info, &format!("[ALLOW] {}", event_info));
            }
            RuleAction::Warn => {
                logger.log(LogLevel::Warn, &format!("[WARN] {}", event_info));
                notifier::notify_event(&event, rule_name, &decision.action);
            }
            RuleAction::Block => {
                logger.log(LogLevel::Error, &format!("[BLOCK] {}", event_info));
                notifier::notify_event(&event, rule_name, &decision.action);
            }
        }
    }

    Ok(())
}

fn print_usage() {
    println!("[Formic Trace Core]");
    println!("Uso:");
    println!("  formic-core.exe --service    Inicia el demonio de seguridad en segundo plano.");
    println!("  formic-core.exe --cli        Abre el modo CLI interactivo.");
}

fn main() {
    let mode = env::args().nth(1);
    match mode.as_deref() {
        Some("--service") => {
            if let Err(e) = run_service() {
                eprintln!("Error ejecutando el servicio: {}", e);
            }
        }
        Some("--cli") => {
            let args: Vec<String> = env::args().collect();
            cli::run(&args);
        }
        _ => print_usage(),
    }
}
