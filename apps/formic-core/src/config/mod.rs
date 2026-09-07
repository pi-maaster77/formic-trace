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

use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

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
    let json_str = eval_nickel_to_json(path.as_ref())?;
    serde_json::from_str(&json_str).map_err(|e| e.to_string())
}

fn eval_nickel_to_json(_path: &Path) -> Result<String, String> {
    todo!()
}
