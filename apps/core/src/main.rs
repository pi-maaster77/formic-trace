/*
 * File: main.rs                                                               *
 * Path: \main.rs                                                              *
 * Project: src                                                                *
 * Author: pi-maaster77                                                        *
 * Created Date: Sa/10/2026 11:06:27                                           *
 * Last Modified: Sat Oct 17 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

#![forbid(unsafe_code)]

mod logger;
mod domain;
mod engine;
mod cli;
mod config;

use clap::Parser;
use domain::inspectors::certs::CertsInspector;
use engine::calibrate::inspectors::InspectorsCalibrator;
use cli::Cli;
use crate::domain::inspectors::environment;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

fn main() {
    // El main solo crea la instancia; el componente se encarga de todo lo demás
    let args = Cli::parse();
    if args.calibrate {
        let inspectors_calibrator = InspectorsCalibrator::new(args.baseline_output);
        if let Err(error) = inspectors_calibrator.run_calibration() {
            eprintln!("Falló la calibración de certificados: {error:#}");
        }
        return; 
    }
    if args.inspect_environment {
        let _logger_guard = logger::init_component_logger("environment");
        let policy = match config::inspectors::load_environment_policy(&args.inspectors_config) {
            Ok(policy) => policy,
            Err(error) => {
                tracing::error!(error = %error, "Se rechaza el monitoreo: la política Nickel de entorno no es válida.");
                return;
            }
        };
        if let Err(error) = domain::inspectors::environment::inspect(&policy) {
            tracing::error!(error = %error, "Falló la aplicación de la política de entorno.");
        }
        return;
    }
    if args.inspect_system_features {
        let _logger_guard = logger::init_component_logger("system_features");
        let policy = match config::inspectors::load_system_features_policy(&args.inspectors_config) {
            Ok(policy) => policy,
            Err(error) => {
                tracing::error!(error = %error, "Se rechaza el monitoreo: la política Nickel de características del sistema no es válida.");
                return;
            }
        };
        if let Err(error) = domain::inspectors::system_features::inspect(&policy) {
            tracing::error!(error = %error, "Falló la aplicación de la política de características del sistema.");
        }
        return;
    }

    let _logger_guard = logger::init_runtime_logger();
    let environment_policy = match config::inspectors::load_environment_policy(&args.inspectors_config) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("Se rechaza el monitoreo: la política Nickel de entorno no es válida: {error:#}");
            return;
        }
    };
    let system_features_policy = match config::inspectors::load_system_features_policy(&args.inspectors_config) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("Se rechaza el monitoreo: la política Nickel de características del sistema no es válida: {error:#}");
            return;
        }
    };
    let certificate_config =
        config::inspectors::load_certificate_config(&args.inspectors_config);
    let certs_inspector = CertsInspector::new("certs", certificate_config);

    let running = Arc::new(AtomicBool::new(true));
    let signal_flag = Arc::clone(&running);
    if let Err(error) = ctrlc::set_handler(move || {
        signal_flag.store(false, Ordering::Relaxed);
    }) {
        tracing::error!(error = %error, "No se pudo instalar el manejador de apagado.");
        return;
    }

    let certs_running = Arc::clone(&running);
    let certs_thread = thread::spawn(move || {
        let _stop_on_exit = StopOnDrop(certs_running.clone());
        certs_inspector.execute_until_stopped(certs_running.as_ref())
    });

    let environment_running = Arc::clone(&running);
    let environment_thread = thread::spawn(move || {
        let _stop_on_exit = StopOnDrop(environment_running.clone());
        environment::inspect_until_stopped(&environment_policy, environment_running.as_ref())
    });

    let system_features_running = Arc::clone(&running);
    let system_features_thread = thread::spawn(move || {
        let _stop_on_exit = StopOnDrop(system_features_running.clone());
        domain::inspectors::system_features::inspect_until_stopped(
            &system_features_policy,
            system_features_running.as_ref(),
        )
    });

    if let Err(error) = join_inspector("certificados", certs_thread) {
        tracing::error!(error = %error, "Terminó el inspector de certificados con error.");
    }
    if let Err(error) = join_inspector("entorno", environment_thread) {
        tracing::error!(error = %error, "Terminó el inspector de entorno con error.");
    }
    if let Err(error) = join_inspector("características del sistema", system_features_thread) {
        tracing::error!(error = %error, "Terminó el inspector de características del sistema con error.");
    }
}

fn join_inspector(
    name: &str,
    handle: thread::JoinHandle<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => anyhow::bail!("el hilo del inspector {name} terminó por panic"),
    }
}
