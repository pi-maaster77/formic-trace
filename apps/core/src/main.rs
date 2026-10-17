/*
 * File: main.rs                                                               *
 * Path: \main.rs                                                              *
 * Project: src                                                                *
 * Author: pi-maaster77                                                        *
 * Created Date: Sa/10/2026 11:06:27                                           *
 * Last Modified: Thu Oct 15 2026                                              *
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
        if let Err(error) = domain::inspectors::environment::inspect() {
            tracing::error!(error = %error, "Falló el inventario de variables de entorno.");
        }
        return;
    }
    let certificate_config =
        config::inspectors::load_certificate_config(&args.inspectors_config);
    let certs_inspector = CertsInspector::new("certs", certificate_config);
    if let Err(error) = certs_inspector.execute() {
        eprintln!("Falló el inspector de certificados: {error:#}");
    }
}