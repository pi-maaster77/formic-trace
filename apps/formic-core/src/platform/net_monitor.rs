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

use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use crate::shared::models::{NetAction, NetEvent, SystemEvent};

pub struct NetMonitor;

impl NetMonitor {
    pub fn start_watch(tx: Sender<SystemEvent>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
            let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

            loop {
                if let Ok(sockets) = get_sockets_info(af_flags, proto_flags) {
                    for socket in sockets {
                        if let ProtocolSocketInfo::Tcp(tcp_info) = socket.protocol_socket_info {
                            for pid in socket.associated_pids {
                                let net_event = NetEvent {
                                    pid,
                                    local_addr: tcp_info.local_addr.to_string(),
                                    remote_addr: tcp_info.remote_addr.to_string(),
                                    remote_port: tcp_info.remote_port,
                                    protocol: "TCP".to_string(),
                                    action: NetAction::ConnectionEstablished,
                                };
                                let _ = tx.send(SystemEvent::Net(net_event));
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_secs(2));
            }
        })
    }
}
