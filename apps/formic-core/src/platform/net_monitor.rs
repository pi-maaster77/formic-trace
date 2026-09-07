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

use std::collections::HashSet;
use std::sync::mpsc::Sender;
use std::thread;
use sysinfo::Networks;

use crate::config::NetConfig;
use crate::shared::models::{NetEvent, SystemEvent};

pub struct NetMonitor;

impl NetMonitor {
    pub fn start_watch(config: &NetConfig, tx: Sender<SystemEvent>) -> thread::JoinHandle<()> {
        let interval = config.poll_interval();
        let monitored_ports: HashSet<u16> = config.monitored_ports.iter().copied().collect();

        thread::spawn(move || {
            let mut networks = Networks::new_with_refreshed_list();

            loop {
                networks.refresh();

                for (_interface_name, network) in &networks {
                    if !monitored_ports.is_empty() {
                        // Lógica de inspección por puerto si aplica
                    }

                    let rx_bytes = network.received();
                    let tx_bytes = network.transmitted();

                    if tx_bytes > 0 || rx_bytes > 0 {
                        let _ = tx.send(SystemEvent::Net(NetEvent {
                            interface: _interface_name.clone(), // <- Campo faltante
                            pid: 0,
                            local_addr: "127.0.0.1".to_string(),
                            remote_addr: "0.0.0.0".to_string(),
                            remote_port: 0,
                            protocol: "TCP".to_string(),
                            action: "traffic".to_string(),
                            rx_bytes,
                            tx_bytes,
                        }));
                    }
                }

                thread::sleep(interval);
            }
        })
    }
}