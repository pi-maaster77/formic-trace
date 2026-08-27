/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/service/mod.rs
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

use crate::engine::rules::RuleEngine;
use crate::platform::fs_monitor::FileMonitor;
use crate::shared::models::FileEvent;
use std::sync::mpsc;

pub fn start_daemon(watch_path: &str) -> Result<(), String> {
    println!("[Formic Daemon] Inicializando componentes de seguridad...");

    let (tx, rx) = mpsc::channel::<FileEvent>();
    let monitor = FileMonitor::new(watch_path)?;
    let engine = RuleEngine::new();

    // Arranca el worker de Win32 en su propio hilo
    monitor.start_worker(tx);

    println!("[Formic Daemon] Escuchando eventos del sistema...");

    // Bucle principal de consumo de eventos
    for event in rx {
        let decision = engine.evaluate(&event);
        println!(
            "[Formic Daemon] Evento: {:?} | Acción: {:?} | Decisión: {:?}",
            event.path, event.action, decision
        );
    }

    Ok(())
}