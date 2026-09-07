/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/platform/fs_monitor.rs
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

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

use crate::config::FormicConfig; // Importar la config de Nickel
use crate::shared::models::{FileAction, FileEvent, SystemEvent};

pub struct FileMonitor {
    _watcher: RecommendedWatcher,
}

impl FileMonitor {
    pub fn start(config: &FormicConfig, tx: Sender<SystemEvent>) -> Result<Self, String> {
        let watcher_tx = tx;
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    let action = match event.kind {
                        EventKind::Create(_) => Some(FileAction::Created),
                        EventKind::Remove(_) => Some(FileAction::Deleted),
                        EventKind::Modify(_) => Some(FileAction::Modified),
                        _ => None,
                    };

                    if let Some(action) = action {
                        for p in event.paths {
                            let file_event = FileEvent {
                                path: p,
                                action: action.clone(),
                            };
                            let _ = watcher_tx.send(SystemEvent::File(file_event));
                        }
                    }
                }
                Err(e) => eprintln!("[Error en FileWatcher]: {:?}", e),
            },
            Config::default(),
        )
        .map_err(|e| format!("Error al inicializar el watcher: {}", e))?;

        // Iterar sobre las rutas definidas en Nickel (ej. config.fs_watch_paths)
        for path_str in &config.fs.watch_paths {
            let path = PathBuf::from(path_str);
            if path.exists() {
                watcher
                    .watch(&path, RecursiveMode::Recursive)
                    .map_err(|e| format!("No se pudo monitorear '{}': {}", path.display(), e))?;
            }
        }

        Ok(Self { _watcher: watcher })
    }
}