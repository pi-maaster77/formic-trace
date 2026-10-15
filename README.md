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


---

### Filosofia
La idea seria intentar traer todo lo posible la filosofia unix (el usuario tiene la ultima palabra, incluso si se quiere pegar un tiro en el pie) a un entorno de windows
como NT no fue diseñado para esto, se intentara acercarce lo mas posible a esta filosofia. 

---

**En resumen:** Formic combina la rigidez determinista de la infraestructura moderna (tipo Nix o Kubernetes) con la simplicidad de un panel visual e interactivo, convirtiendo los mecanismos nativos de Windows en un escudo de seguridad inexpugnable.

---

## Inspector de certificados raíz

`formic-core` evalúa la política con el ejecutable Nickel. Instálalo en una ubicación protegida y pásalo con `--nickel-binary` en servicios; el valor `nickel` usa el `PATH` y se recomienda solo para desarrollo. La ruta de configuración predeterminada es `config/default.ncl`.

El archivo global `config/default.ncl` importa las configuraciones Nickel por inspector desde `config/inspectors/<inspector>/`; las políticas viven en `config/policies/<politica>/`. Las carpetas de hardware, identidad y características del sistema agregan sus subcarpetas mediante su propio `default.ncl`. La configuración de certificados está en `config/inspectors/certs/default.ncl`.

El preset inicial es `alert_only` y no borra certificados. Para capturar la línea base ejecuta `formic-core --calibrate`; se guarda como SHA-256 en `config/inspectors/certs/baseline.toml` sin modificar el almacén. `minimal` consume esa lista. Cualquier modo que elimine certificados requiere `allow_destructive = true`; revisa la política antes de habilitarlo. `purge_all` elimina todo el almacén `LocalMachine\\Root`.

Para importar una CA de terceros, coloca un archivo `.cer`, `.crt` o `.pem` (un certificado por archivo) en `config/inspectors/certs/third_party/` y enumera su ruta relativa en `import_certificates`. Requiere `allow_import = true`, un modo distinto de `alert_only` y `allow_destructive = true`. La política activa también debe permitir la huella: inclúyela en `baseline_sha256` para `minimal` o en `allow_sha256` para `whitelist`. Se importan solo certificados CA vigentes; la operación es idempotente y requiere permisos de escritura para `LocalMachine\\Root`. Verifica las huellas por un canal independiente antes de confiar en un certificado.

Si Nickel no está disponible o la configuración no valida, el inspector registra el error y usa el modo de emergencia `alert_only`.

## Licencia

Este proyecto se distribuye bajo la licencia **GNU General Public License v3.0 (GPLv3)**. 

### Excepción para archivos de configuración
Los archivos de configuración y reglas declarativas ubicados dentro del directorio `/config/` se distribuyen bajo la **Licencia MIT** para permitir que los usuarios y administradores adapten, reutilicen y compartan sus políticas libremente sin restricciones de Copyleft.
