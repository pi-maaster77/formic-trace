# Formic Trace - Declarative Application Whitelisting for Windows
# File: /config/default.ncl
# 
# Copyright (C) 2026 pi-maaster77 and Formic Trace Contributors
# 
# SPDX-License-Identifier: MIT
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

let Action = [| 'allow, 'block, 'audit |] in
let Policy = [| 'deny, 'allow |] in

let RuleContract = {
  name | String,
  path_pattern | String | optional,
  sha256 | String | optional,
  verify_signature | Bool | optional,
  action | Action,
} in

{
  # Política por defecto del motor
  default_policy | Policy = 'deny,

  # Lista de reglas de excepción
  rules | Array RuleContract = [
    {
      name = "Permitir Binarios Firmados por Microsoft Windows",
      path_pattern = "C:\\Windows\\System32\\*.exe",
      verify_signature = true,
      action = 'allow,
    },
    {
      name = "Permitir Archivos de Programas (Requiere Firma)",
      path_pattern = "C:\\Program Files\\*.exe",
      verify_signature = true,
      action = 'allow,
    },
    {
      name = "Bloquear Ejecución en Carpetas Temporales (Temp / AppData)",
      path_pattern = "*\\AppData\\Local\\Temp\\*.exe",
      action = 'block,
    }
  ]
}