/*
 * File: mod.rs                                                                *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\cli\mod.rs                     *
 * Project: cli                                                                *
 * Author: pi-maaster77                                                        *
 * Created Date: Th/10/2026 15:30:05                                           *
 * Last Modified: Thu Oct 15 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "formic-core")]
#[command(about = "Motor de seguridad Default-Deny para Windows", version = "0.1.0")]
pub struct Cli {
    /// Ejecuta el modo aprendizaje para calibrar la línea base del sistema (certificados, etc.)
    #[arg(long, default_value_t = false)]
    pub calibrate: bool,

    /// Ruta personalizada opcional para guardar la línea base generada
    #[arg(long, value_name = "FILE", default_value = "config/inspectors/certs/baseline.toml")]
    pub baseline_output: PathBuf,

    /// Configuración Nickel para la política de certificados raíz
    #[arg(long, value_name = "FILE", default_value = "config/default.ncl")]
    pub inspectors_config: PathBuf,

}