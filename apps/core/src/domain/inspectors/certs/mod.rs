/*
 * File: mod.rs                                                                *
 * Path: \mod.rs                                                               *
 * Project: certs                                                              *
 * Author: pi-maaster77                                                        *
 * Created Date: We/10/2026 16:02:19                                           *
 * Last Modified: Wed Oct 14 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use crate::logger::{self, ComponentLoggerGuard};
use tracing::info;

pub struct CertsInspector {
    component_name: String,
    _logger_guard: ComponentLoggerGuard, // Retenemos el guard aquí
}

impl CertsInspector {
    pub fn new(component_name: &str) -> Self {
        // Inicializamos el logger y guardamos el guard
        let guard = logger::init_component_logger(component_name);

        info!(component = component_name, "Instancia creada y logger inicializado.");

        Self {
            component_name: component_name.to_string(),
            _logger_guard: guard,
        }
    }

    pub fn execute(&self) {
        info!(
            component = %self.component_name,
            "Ejecutando rutina principal del inspector de certificados..."
        );

        // Todo sale por tracing, nada de println suelto que escape al log
        info!(
            component = %self.component_name,
            "¡Hola Mundo! Certs inicializado correctamente."
        );
    }
}