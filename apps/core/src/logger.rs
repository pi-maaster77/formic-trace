/*
 * File: logger.rs                                                             *
 * Path: \logger.rs                                                            *
 * Project: src                                                                *
 * Author: pi-maaster77                                                        *
 * Created Date: We/10/2026 16:01:57                                           *
 * Last Modified: Wed Oct 14 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use std::fs;
use std::path::PathBuf;
use chrono::Utc;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub struct ComponentLoggerGuard {
    _worker_guard: Option<WorkerGuard>,
    current_file_path: PathBuf,
    timestamp_file_path: PathBuf,
}

impl Drop for ComponentLoggerGuard {
    fn drop(&mut self) {
        // Tomamos el guard para forzar su liberación sin violar el préstamo mutable
        let _ = self._worker_guard.take();

        std::thread::sleep(std::time::Duration::from_millis(50));

        if self.current_file_path.exists() {
            let _ = fs::copy(&self.current_file_path, &self.timestamp_file_path);
            let _ = fs::remove_file(&self.current_file_path);
        }
    }
}

pub fn init_component_logger(component_name: &str) -> ComponentLoggerGuard {
    let dir_path = format!("logs/{}", component_name);
    fs::create_dir_all(&dir_path).unwrap_or_default();

    let current_file_path = PathBuf::from(&dir_path).join("current.log");
    
    let now = Utc::now();
    let timestamp_str = now.format("%Y-%m-%d_%H-%M-%S").to_string();
    let timestamp_file_path = PathBuf::from(&dir_path).join(format!("{}.log", timestamp_str));

    let _ = fs::write(&current_file_path, "");

    let file_appender = tracing_appender::rolling::RollingFileAppender::new(
        tracing_appender::rolling::Rotation::NEVER,
        &dir_path,
        "current.log",
    );
    let (non_blocking, worker_guard) = tracing_appender::non_blocking(file_appender);

    let _ = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(false),
        )
        .with(
            fmt::layer()
                .with_writer(std::io::stdout)
                .with_target(true),
        )
        .try_init();

    ComponentLoggerGuard {
        _worker_guard: Some(worker_guard),
        current_file_path,
        timestamp_file_path,
    }
}