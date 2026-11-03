/*
 * File: nickel.rs                                                             *
 * Path: b:\Proyectos\rust\Formic\apps\core\src\config\inspectors\nickel.rs    *
 * Project: inspectors                                                         *
 * Author: pi-maaster77                                                        *
 * Created Date: Su/10/2026 02:54:18                                           *
 * Last Modified: Sun Oct 18 2026                                              *
 *                                                                             *
 * License: GNU General Public License v3.0 (GPLv3)                            *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU General Public License as published by        *
 * the Free Software Foundation, either version 3 of the License, or           *
 * (at your option) any later version.                                         *
 */

use nickel_lang::ErrorFormat as NickelErrorFormat;

pub(super) fn format_nickel_error(error: nickel_lang::Error) -> String {
    let mut formatted = Vec::new();
    if error
        .format(&mut formatted, NickelErrorFormat::Text)
        .is_ok()
    {
        String::from_utf8_lossy(&formatted).into_owned()
    } else {
        format!("{error:?}")
    }
}