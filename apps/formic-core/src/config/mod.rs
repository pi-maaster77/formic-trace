/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/config/mod.rs
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

use serde::Deserialize;
use std::fs::File;
use std::io::Cursor;
use std::path::Path;
use std::time::Duration;

use nickel_lang_core::{
    eval::cache::lazy::CBNCache,
    program::ProgramBuilder,
    serialize::{self, ExportFormat},
};

use crate::shared::models::RuleAction;

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub name: String,
    pub path_pattern: String,
    pub action: RuleAction,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FsConfig {
    pub monitor: bool,
    #[serde(default)]
    pub watch_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetConfig {
    pub monitor: bool,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default)]
    pub monitored_ports: Vec<u16>,
}

impl NetConfig {
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProcessConfig {
    pub monitor: bool,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    pub track_cmdline: bool,
}

impl ProcessConfig {
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegistryConfig {
    pub monitor: bool,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default)]
    pub keys_to_watch: Vec<String>,
}

impl RegistryConfig {
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }
}

fn default_poll_interval_ms() -> u64 {
    1000
}

#[derive(Debug, Deserialize, Clone)]
pub struct FormicConfig {
    pub fs: FsConfig,
    pub net: NetConfig,
    pub process: ProcessConfig,
    pub registry: RegistryConfig,
    pub rules: Vec<Rule>,
    pub default_action: RuleAction,
}

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<FormicConfig, String> {
    let path_ref = path.as_ref();

    let file = File::open(path_ref)
        .map_err(|e| format!("Error al abrir archivo '{:?}': {}", path_ref, e))?;

    // Especificamos explícitamente CBNCache al llamar a .build()
    let mut program = ProgramBuilder::new()
        .add_source(file, path_ref.as_os_str().to_os_string())
        .build::<CBNCache>()
        .map_err(|e| format!("Error al construir programa Nickel: {:?}", e))?;

    let evaluated = program
        .eval_full_for_export()
        .map_err(|e| format!("Error evaluando script Nickel '{:?}': {:?}", path_ref, e))?;

    let mut buffer = Vec::new();
    serialize::to_writer(&mut buffer, ExportFormat::Json, &evaluated)
        .map_err(|e| format!("Error serializando resultado Nickel a JSON: {:?}", e))?;

    serde_json::from_reader(Cursor::new(buffer))
        .map_err(|e| format!("Error deserializando JSON a FormicConfig: {}", e))
}