
/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/platform/registry_monitor.rs
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

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use winreg::enums::*;
use winreg::RegKey;

use crate::shared::models::{RegAction, RegistryEvent, SystemEvent};

pub struct RegistryMonitor;

impl RegistryMonitor {
    pub fn start_watch(tx: Sender<SystemEvent>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            // Mapa para mantener el estado anterior de las claves y sus valores
            let mut known_values: HashMap<String, String> = HashMap::new();

            // Rutas típicas de persistencia para monitorear
            let keys_to_watch = vec![
                (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ];

            loop {
                for &(hkey, path) in &keys_to_watch {
                    let hk = RegKey::predef(hkey);
                    if let Ok(key) = hk.open_subkey_with_flags(path, KEY_READ) {
                        for item in key.enum_values().flatten() {
                            let (val_name, val_data) = item;
                            let full_key_id = format!(r"{}\{}", path, val_name);
                            let current_value_str = val_data.to_string();

                            match known_values.get(&full_key_id) {
                                None => {
                                    // Nuevo valor creado en el registro
                                    let reg_event = RegistryEvent {
                                        key_path: path.to_string(),
                                        value_name: val_name,
                                        action: RegAction::KeyCreated,
                                        pid: None,
                                    };
                                    let _ = tx.send(SystemEvent::Registry(reg_event));
                                    known_values.insert(full_key_id, current_value_str);
                                }
                                Some(old_value) if old_value != &current_value_str => {
                                    // Valor existente modificado
                                    let reg_event = RegistryEvent {
                                        key_path: path.to_string(),
                                        value_name: val_name,
                                        action: RegAction::ValueModified,
                                        pid: None,
                                    };
                                    let _ = tx.send(SystemEvent::Registry(reg_event));
                                    known_values.insert(full_key_id, current_value_str);
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Detección de valores eliminados
                let mut deleted_keys = Vec::new();
                for (full_key_id, _) in &known_values {
                    // Verificar si la clave aún existe en el registro
                    let mut exists = false;
                    for &(hkey, path) in &keys_to_watch {
                        let hk = RegKey::predef(hkey);
                        if let Ok(key) = hk.open_subkey_with_flags(path, KEY_READ) {
                            if let Some(val_name) = full_key_id.strip_prefix(&format!(r"{}\", path)) {
                                if key.get_raw_value(val_name).is_ok() {
                                    exists = true;
                                    break;
                                }
                            }
                        }
                    }

                    if !exists {
                        deleted_keys.push(full_key_id.clone());
                    }
                }

                for deleted in deleted_keys {
                    known_values.remove(&deleted);
                    let reg_event = RegistryEvent {
                        key_path: deleted.clone(),
                        value_name: deleted,
                        action: RegAction::ValueDeleted,
                        pid: None,
                    };
                    let _ = tx.send(SystemEvent::Registry(reg_event));
                }

                thread::sleep(Duration::from_secs(3));
            }
        })
    }
}