/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/platform/net_monitor.rs
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
use crate::shared::models::SystemEvent;

pub struct NetMonitor;

impl NetMonitor {
    pub fn start_watch(_tx: Sender<SystemEvent>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            // TODO: Enumerar sockets TCP/UDP activos vinculados a PIDs
            loop {
                thread::sleep(std::time::Duration::from_secs(3));
            }
        })
    }
}