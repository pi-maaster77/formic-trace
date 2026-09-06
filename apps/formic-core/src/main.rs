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

use logger::{LogLevel, Logger};
use shared::models::RuleAction;
use crate::shared::models::{Config, SystemEvent};

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

fn run_service() {
    let logger = Logger::new(Some("formic.log"));
    logger.log(LogLevel::Info, "Inicializando Formic Core Daemon...");

    let config_path = Path::new("formic.json");
    let config = match config::load_config(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            logger.log(
                LogLevel::Warn,
                &format!("Configuración no cargada ({}), aplicando fallback por defecto.", err),
            );
            Config {
                watch_paths: vec![resolve_watch_dir(None).to_string_lossy().to_string()],
                default_action: RuleAction::Allow,
                rules: vec![],
            }
        }
    };

    let first_watch_path = config.watch_paths.first().map(|s| s.as_str());
    let watch_path = resolve_watch_dir(first_watch_path);
    logger.log(
        LogLevel::Info,
        &format!("Monitoreando directorio: {}", watch_path.display()),
    );

    // Canal MPSC unificado para todos los monitores
    let (tx, rx) = mpsc::channel::<SystemEvent>();

    let _fs_monitor = platform::fs_monitor::FileMonitor::new(&watch_path, tx.clone());
    let _proc_monitor = platform::process_monitor::ProcessMonitor::start(tx.clone());
    let _reg_monitor = platform::registry_monitor::RegistryMonitor::start_watch(tx.clone());
    let _net_monitor = platform::net_monitor::NetMonitor::start_watch(tx.clone());

    logger.log(LogLevel::Info, "Servicio de monitoreo iniciado. Escuchando eventos...");

    // Único bucle de procesamiento de eventos en la cola
    for event in rx {
        let decision = engine::evaluator::evaluate(&event, &config);
        let rule_name = decision.matched_rule.unwrap_or("DefaultPolicy");

        // Formateo descriptivo según la variante recibida
        let event_info = match &event {
            SystemEvent::File(e) => format!("FS: {:?} | Acción: {:?}", e.path, e.action),
            SystemEvent::Process(e) => format!("PROC: {:?} (PID: {})", e.path, e.pid),
            SystemEvent::Registry(e) => format!("REG: {:?}", e.key_path),
            SystemEvent::Net(e) => format!("NET: {}:{}", e.remote_addr, e.remote_port),
        };

        match decision.action {
            RuleAction::Allow => {
                logger.log(
                    LogLevel::Info,
                    &format!("[ALLOW] {}", event_info),
                );
            }
            RuleAction::Warn => {
                logger.log(
                    LogLevel::Warn,
                    &format!("[WARN] {}", event_info),
                );
                notifier::notify_event(&event, rule_name, &decision.action);
            }
            RuleAction::Block => {
                logger.log(
                    LogLevel::Error,
                    &format!("[BLOCK] {}", event_info),
                );
                notifier::notify_event(&event, rule_name, &decision.action);
            }
        }
    }
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
        Some("--service") => run_service(),
        Some("--cli") => {
            let args: Vec<String> = env::args().collect();
            cli::run(&args);
        }
        _ => print_usage(),
    }
}