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

mod config;
mod engine;
mod logger;
mod notifier;
mod platform;
mod shared;
mod cli;

use std::env;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::mpsc;

use logger::{LogLevel, Logger};
use shared::models::RuleAction;

/// Resuelve una ruta válida para monitorear en disco
fn resolve_watch_dir(configured_path: Option<&str>) -> PathBuf {
    // 1. Si hay una ruta especificada en el archivo de configuración y existe, la usa
    if let Some(path_str) = configured_path {
        let p = PathBuf::from(path_str);
        if p.exists() {
            return p;
        }
    }

    // 2. Fallback a la carpeta Temp del perfil de usuario (%USERPROFILE%\AppData\Local\Temp)
    if let Ok(user_profile) = env::var("USERPROFILE") {
        let user_temp = PathBuf::from(user_profile).join(r"AppData\Local\Temp");
        if user_temp.exists() {
            return user_temp;
        }
    }

    // 3. Fallback a la variable %TEMP%
    if let Ok(temp_env) = env::var("TEMP") {
        let temp_path = PathBuf::from(temp_env);
        if temp_path.exists() {
            return temp_path;
        }
    }

    // 4. Fallback final al directorio de ejecución actual
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn run_service() {
    let logger = Logger::new(Some("formic.log"));
    logger.log(LogLevel::Info, "Inicializando Formic Core Daemon...");

    // Cargar archivo de configuración declarativo
    let config_path = Path::new("formic.json");
    let config = match config::load_config(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            logger.log(
                LogLevel::Warn,
                &format!("Configuración no cargada ({}), aplicando fallback por defecto.", err),
            );
            shared::models::Config {
                watch_path: resolve_watch_dir(None).to_string_lossy().to_string(),
                default_action: RuleAction::Allow,
                rules: vec![],
            }
        }
    };

    // Validar y resolver la ruta final a monitorear
    let watch_path = resolve_watch_dir(Some(&config.watch_path));
    logger.log(
        LogLevel::Info,
        &format!("Monitoreando directorio: {}", watch_path.display()),
    );

    // Canal de comunicación MPSC (Productor: FileMonitor, Consumidor: Engine Loop)
    let (tx, rx) = mpsc::channel();

    // Inicializar el monitor de archivos sin unsafe mediante 'notify'
    let _monitor = match platform::fs_monitor::FileMonitor::new(&watch_path, tx) {
        Ok(m) => m,
        Err(err) => {
            logger.log(
                LogLevel::Error,
                &format!("Error fatal al iniciar monitor: {}", err),
            );
            exit(1);
        }
    };

    logger.log(LogLevel::Info, "Servicio de monitoreo iniciado. Escuchando eventos...");

    // Bucle principal de consumo de eventos (Pegamento)
    for event in rx {
        let decision = engine::evaluator::evaluate(&event, &config);
        let rule_name = decision.matched_rule.unwrap_or("DefaultPolicy");

        match decision.action {
            RuleAction::Allow => {
                logger.log(
                    LogLevel::Info,
                    &format!("[ALLOW] Path: {:?} | Acción: {:?}", event.path, event.action),
                );
            }
            RuleAction::Warn => {
                logger.log(
                    LogLevel::Warn,
                    &format!("[WARN] Path: {:?} | Acción: {:?}", event.path, event.action),
                );
                notifier::notify_event(&event, rule_name, &decision.action);
            }
            RuleAction::Block => {
                logger.log(
                    LogLevel::Error,
                    &format!("[BLOCK] Path: {:?} | Acción: {:?}", event.path, event.action),
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