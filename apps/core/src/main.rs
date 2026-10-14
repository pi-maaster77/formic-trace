/*
 * File: main.rs                                                               *
 * Path: \main.rs                                                              *
 * Project: src                                                                *
 * Author: pi-maaster77                                                        *
 * Created Date: Sa/10/2026 11:06:27                                           *
 * Last Modified: Wed Oct 14 2026                                              *
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

use domain::inspectors::certs::CertsInspector;

fn main() {
    // El main solo crea la instancia; el componente se encarga de todo lo demás
    let certs_inspector = CertsInspector::new("certs");
    certs_inspector.execute();
}