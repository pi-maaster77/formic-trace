/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/engine/config/mod.rs
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

use crate::shared::models::Config;
use std::fs;
use std::path::Path;

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, String> {
    let file_path = path.as_ref();
    
    if !file_path.exists() {
        return Err(format!("El archivo de configuración no existe: {}", file_path.display()));
    }

    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("Error al leer {}: {}", file_path.display(), e))?;

    let config: Config = serde_json::from_str(&content)
        .map_err(|e| format!("Error al parsear JSON de configuración: {}", e))?;

    Ok(config)
}