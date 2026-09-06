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
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use sysinfo::{ProcessRefreshKind, System};

use crate::shared::models::{ProcessAction, ProcessEvent, SystemEvent};

pub struct ProcessMonitor;

impl ProcessMonitor {
    pub fn start(tx: Sender<SystemEvent>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut sys = System::new();
            let mut known_pids = HashSet::new();

            loop {
                sys.refresh_processes_specifics(ProcessRefreshKind::everything());

                let current_pids: HashSet<_> = sys.processes().keys().copied().collect();

                // Detección de nuevos procesos (Spawned)
                for pid in current_pids.difference(&known_pids) {
                    if let Some(proc_) = sys.process(*pid) {
                        let proc_event = ProcessEvent {
                            pid: pid.as_u32(),
                            ppid: proc_.parent().map(|p| p.as_u32()).unwrap_or(0),
                            path: proc_.exe().map(|p| p.to_path_buf()).unwrap_or_default(),
                            command_line: proc_.cmd().join(" "),
                            action: ProcessAction::Spawned,
                        };
                        let _ = tx.send(SystemEvent::Process(proc_event));
                    }
                }

                known_pids = current_pids;
                thread::sleep(Duration::from_millis(500));
            }
        })
    }
}
