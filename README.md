**Formic** es un motor de seguridad de **Whitelist/Default-Deny** para Windows, ligero y ultrarrápido, desarrollado en **Rust** e impulsado por **Nickel**. Su objetivo es erradicar la incertidumbre en el software: si un ejecutable o biblioteca no está explícitamente declarado, firmado o verificado por hash, **simplemente no se ejecuta**.

---

### Lo que pretende hacer

* **Cero Confianza (Default-Deny):** En lugar de buscar malware conocido por firmas (como un antivirus tradicional), bloquea absolutamente todo lo que no esté en su lista de permitidos (`formic.ncl`).
* **Soporte sin Infierno ("Funciona en mi máquina"):** Aprovecha el determinismo estricto. Si una configuración no replica un error, el problema es una inconsistencia del motor, garantizando comportamiento matemático exacto.
---

### Arquitectura en 3 Capas

```text
┌─────────────────────────────────────────────────────────┐
│                    GUI / CLI Clients                    │
│ • Vista Grilla (Estilo Access)      • Modo Admin/User   │
└────────────────────────────┬────────────────────────────┘
                             │  IPC (Named Pipes / JSON)
┌────────────────────────────▼────────────────────────────┐
│                    Formic Core Engine                   │
│ • Rust Daemon (SYSTEM)              • WinAPI / Hasher   │
└────────────────────────────┬────────────────────────────┘
                             │  Bindings Rust
┌────────────────────────────▼────────────────────────────┐
│                   Sandbox de Nickel                     │
│ • Motor de Reglas Dinámicas    • Hardening de Windows   │
└─────────────────────────────────────────────────────────┘

```

1. **Unidad Ejecutable Multillamada (`formic.exe`):** Un único binario compilado en Rust desde Linux (cross-compilation con MinGW) que asume roles de servicio `SYSTEM`, GUI o cliente CLI según la invocación.
2. **Core en Rust (Las Manos):** Un servicio de fondo permanente que interactúa con la API nativa de Windows (`WinVerifyTrust`, `ReadDirectoryChangesW`, ETW), garantizando seguridad de memoria, rendimiento tipo C++ y cero colapsos.
3. **Control Total en Nickel (El Cerebro):** Un motor de reglas dinámicas que recibe datos de Rust y extiende el control del sistema. Permite gestionar servicios, claves del Registro, firewall o políticas mediante scripts sencillos.
4. **Interfaz Dual para el Usuario:**
* **Vista "Estilo Access":** Una grilla visual ultra intuitiva con interruptores para activar/desactivar programas o conjuntos de reglas sin escribir código.
* **Vista de Código:** Editor integrado con resaltado de sintaxis para personalizar directamente el `formic.json` o las funciones en Nickel.



---

**En resumen:** Formic combina la rigidez determinista de la infraestructura moderna (tipo Nix o Kubernetes) con la simplicidad de un panel visual e interactivo, convirtiendo los mecanismos nativos de Windows en un escudo de seguridad inexpugnable.

