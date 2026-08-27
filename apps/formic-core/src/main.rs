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
mod engine;
mod platform;
mod service;
mod shared;

use std::env;
use std::path::{Path, PathBuf};
use std::process::exit;

fn resolve_watch_dir() -> PathBuf {
    // 1. Intentar usar la carpeta Temp del perfil de usuario actual (Siempre accesible)
    if let Ok(user_profile) = env::var("USERPROFILE") {
        let user_temp = PathBuf::from(user_profile).join(r"AppData\Local\Temp");
        if user_temp.exists() {
            return user_temp;
        }
    }

    // 2. Fallback a la variable de entorno %TEMP%
    if let Ok(temp_env) = env::var("TEMP") {
        let temp_path = PathBuf::from(temp_env);
        if temp_path.exists() {
            return temp_path;
        }
    }

    // 3. Fallback al directorio actual
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}
fn print_usage() {
    println!("[Formic] Ejecutable invocado sin flags válidas.");
    println!("Uso:");
    println!("  formic.exe --service    Inicia el servicio de monitoreo en segundo plano.");
    println!("  formic.exe --cli        Abre la interfaz de línea de comandos.");
}

fn main() {
    // Saltamos el primer argumento (ruta del binario)
    let mode = env::args().nth(1);

    match mode.as_deref() {
        Some("--service") => {
            let watch_dir = resolve_watch_dir();
            println!("[Formic Daemon] Monitoreando directorio: {}", watch_dir.display());

            if let Err(e) = service::start_daemon(&watch_dir.to_string_lossy()) {
                eprintln!("[Error Fatal Daemon]: {}", e);
                exit(1);
            }
        }
        Some("--cli") => {
            let args: Vec<String> = env::args().collect();
            cli::run(&args);
        }
        _ => {
            print_usage();
        }
    }
}
