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

use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use crate::shared::models::SystemEvent;

pub struct ProcessMonitor;

impl ProcessMonitor {
    pub fn start(_tx: Sender<SystemEvent>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            // Aquí se consulta la tabla de procesos en bucle o vía ETW
            loop {
                // TODO: Enumerar procesos activos o capturar eventos de WMI/ETW
                thread::sleep(Duration::from_secs(2));
            }
        })
    }
}