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
use tracing::Metadata;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{
    filter::filter_fn, fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

pub struct ComponentLoggerGuard {
    worker_guards: Vec<WorkerGuard>,
    current_file_paths: Vec<PathBuf>,
}

impl Drop for ComponentLoggerGuard {
    fn drop(&mut self) {
        self.worker_guards.clear();
        for path in &self.current_file_paths {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn init_component_logger(component_name: &str) -> ComponentLoggerGuard {
    let (current_writer, timestamp_writer, worker_guards, current_file_path) =
        create_component_writers(component_name);

    let _ = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            fmt::layer()
                .with_writer(current_writer)
                .with_ansi(false)
                .with_target(false),
        )
        .with(
            fmt::layer()
                .with_writer(timestamp_writer)
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
        worker_guards,
        current_file_paths: vec![current_file_path],
    }
}

pub fn init_runtime_logger() -> ComponentLoggerGuard {
    let (certs_current, certs_timestamp, mut worker_guards, certs_current_path) =
        create_component_writers("certs");
    let (environment_current, environment_timestamp, environment_workers, environment_current_path) =
        create_component_writers("environment");
    worker_guards.extend(environment_workers);

    let _ = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            fmt::layer()
                .with_writer(certs_current)
                .with_ansi(false)
                .with_target(false)
                .with_filter(filter_fn(|metadata| is_component_target(metadata, "certs"))),
        )
        .with(
            fmt::layer()
                .with_writer(certs_timestamp)
                .with_ansi(false)
                .with_target(false)
                .with_filter(filter_fn(|metadata| is_component_target(metadata, "certs"))),
        )
        .with(
            fmt::layer()
                .with_writer(environment_current)
                .with_ansi(false)
                .with_target(false)
                .with_filter(filter_fn(|metadata| is_component_target(metadata, "environment"))),
        )
        .with(
            fmt::layer()
                .with_writer(environment_timestamp)
                .with_ansi(false)
                .with_target(false)
                .with_filter(filter_fn(|metadata| is_component_target(metadata, "environment"))),
        )
        .with(
            fmt::layer()
                .with_writer(std::io::stdout)
                .with_target(true),
        )
        .try_init();

    ComponentLoggerGuard {
        worker_guards,
        current_file_paths: vec![certs_current_path, environment_current_path],
    }
}

fn is_component_target(metadata: &Metadata<'_>, component_name: &str) -> bool {
    target_matches_component(metadata.target(), component_name)
}

fn target_matches_component(target: &str, component_name: &str) -> bool {
    target.contains(&format!("inspectors::{component_name}"))
}

fn create_component_writers(
    component_name: &str,
) -> (NonBlocking, NonBlocking, Vec<WorkerGuard>, PathBuf) {
    let dir_path = format!("logs/{}", component_name);
    fs::create_dir_all(&dir_path).unwrap_or_default();

    let current_file_path = PathBuf::from(&dir_path).join("current.log");
    let now = Utc::now();
    let timestamp_str = now.format("%Y-%m-%d_%H-%M-%S%.3f").to_string();
    let timestamp_file_path = PathBuf::from(&dir_path).join(format!("{}.log", timestamp_str));

    let _ = fs::write(&current_file_path, "");
    let _ = fs::write(&timestamp_file_path, "");

    let current_file_appender = tracing_appender::rolling::RollingFileAppender::new(
        tracing_appender::rolling::Rotation::NEVER,
        &dir_path,
        "current.log",
    );
    let timestamp_file_appender = tracing_appender::rolling::RollingFileAppender::new(
        tracing_appender::rolling::Rotation::NEVER,
        &dir_path,
        format!("{}.log", timestamp_str),
    );
    let (current_writer, current_worker_guard) = tracing_appender::non_blocking(current_file_appender);
    let (timestamp_writer, timestamp_worker_guard) =
        tracing_appender::non_blocking(timestamp_file_appender);

    (
        current_writer,
        timestamp_writer,
        vec![current_worker_guard, timestamp_worker_guard],
        current_file_path,
    )
}

#[cfg(test)]
mod tests {
    use super::target_matches_component;

    #[test]
    fn routes_inspector_targets_to_their_own_component_logs() {
        let certs_target = "formic_core::domain::inspectors::certs::store";
        let environment_target = "formic_core::domain::inspectors::environment";

        assert!(target_matches_component(certs_target, "certs"));
        assert!(!target_matches_component(certs_target, "environment"));
        assert!(target_matches_component(environment_target, "environment"));
        assert!(!target_matches_component(environment_target, "certs"));
    }
}