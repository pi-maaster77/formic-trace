/*
* Formic Trace - Declarative Application Whitelisting for Windows
* File: /apps/formic-core/src/logger.rs
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

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub enum LogLevel {
    Info,
    Warn,
    Error,
}

pub struct Logger {
    file_path: Option<String>,
}

impl Logger {
    pub fn new(log_file: Option<&str>) -> Self {
        Self {
            file_path: log_file.map(|s| s.to_string()),
        }
    }

    pub fn log(&self, level: LogLevel, message: &str) {
        let prefix = match level {
            LogLevel::Info => "[INFO]",
            LogLevel::Warn => "[WARN]",
            LogLevel::Error => "[ERROR]",
        };

        let formatted = format!("{} {}", prefix, message);
        println!("{}", formatted);

        if let Some(ref path) = self.file_path {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(Path::new(path)) {
                let _ = writeln!(file, "{}", formatted);
            }
        }
    }
}