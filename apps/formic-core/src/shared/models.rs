/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/shared/models.rs
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

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileAction {
    Created,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegAction {
    KeyCreated,
    ValueModified,
    ValueDeleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessAction {
    Spawned,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetAction {
    ConnectionEstablished,
    Listening,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleAction {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub path_pattern: String,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub watch_paths: Vec<String>,
    pub default_action: RuleAction,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision<'a> {
    pub action: RuleAction,
    pub matched_rule: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub path: PathBuf,
    pub action: FileAction,
}

#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub path: PathBuf,
    pub command_line: String,
    pub action: ProcessAction,
}

#[derive(Debug, Clone)]
pub struct RegistryEvent {
    pub key_path: String,
    pub value_name: String,
    pub action: RegAction,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct NetEvent {
    pub pid: u32,
    pub local_addr: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub action: NetAction,
}

#[derive(Debug, Clone)]
pub enum SystemEvent {
    File(FileEvent),
    Registry(RegistryEvent),
    Process(ProcessEvent),
    Net(NetEvent),
}