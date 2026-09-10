# Formic Trace - Declarative Application Whitelisting for Windows
# File: config.ncl
#
# Copyright (c) 2026 pi-maaster77 and Formic Trace Contributors
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

let RuleAction = {
  Allow = "Allow",
  Warn = "Warn",
  Block = "Block",
} in

{
  fs = {
    monitor = true,
    watch_paths = [
      "C:\\Windows\\System32",
      "C:\\Program Files",
    ],
  },

  net = {
    monitor = true,
    poll_interval_ms = 500,
    monitored_ports = [80, 443, 8080],
  },

  process = {
    monitor = true,
    poll_interval_ms = 1000,
    track_cmdline = true,
  },

  registry = {
    monitor = false,
    poll_interval_ms = 2000,
    keys_to_watch = [
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ],
  },

  default_action = RuleAction.Block,

  rules = [
    {
      name = "Auditar ejecuciones en Temp",
      path_pattern = "C:\\Users\\*\\AppData\\Local\\Temp\\*.exe",
      action = RuleAction.Warn, # Usa Warn en vez de Audit
    },
  ],
}