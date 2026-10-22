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

`formic-core` evalúa Nickel en proceso mediante la librería `nickel-lang`; no requiere instalar ni localizar un ejecutable `nickel`. La ruta de configuración predeterminada es `config/default.ncl`.

El archivo global `config/default.ncl` importa las configuraciones Nickel por inspector desde `config/inspectors/<inspector>/`; las políticas viven en `config/policies/<politica>/`. Las carpetas de hardware, identidad y características del sistema agregan sus subcarpetas mediante su propio `default.ncl`. La configuración de certificados está en `config/inspectors/certs/default.ncl`.

El preset inicial es `alert_only` y no borra certificados. Para capturar la línea base ejecuta `formic-core --calibrate`; se guarda como SHA-256 en `config/inspectors/certs/baseline.toml` sin modificar el almacén. `minimal` consume esa lista. Cualquier modo que elimine certificados requiere `allow_destructive = true`; revisa la política antes de habilitarlo. `purge_all` elimina todo el almacén `LocalMachine\\Root`.

En modo `whitelist`, se conserva un certificado si coincide su propia huella en `allow_sha256` **o** la huella SHA-256 de su nombre issuer DER en `allow_issuer_name_sha256`. Los denies (`deny_sha256` y `deny_issuer_name_sha256`) tienen prioridad sobre ambas listas. El hash issuer representa el nombre X.501 exacto, no el certificado emisor.

Para importar un certificado, coloca un archivo `.cer`, `.crt` o `.pem` (un certificado por archivo) en `config/inspectors/certs/third_party/` y enumera su ruta relativa como string en `import_certificates`. La importación está desactivada por defecto. Para la operación explícita configura:

```nickel
mode = 'alert_only,
allow_import = true,
allow_destructive = true,
import_certificates = ["third_party/test_malicious.cer"],
```

Esto también funciona con `mode = 'alert_only`: ese modo no borra certificados por política, pero la importación autorizada sí modifica `LocalMachine\\Root`. Se aceptan CAs válidas y certificados no-CA únicamente si son autofirmados y la firma verifica criptográficamente. La operación es idempotente y requiere permisos de escritura. El certificado de prueba se llama `test_malicious.cer`; instalarlo confía en él como ancla de Windows y puede habilitar suplantación TLS para los nombres que cubra. Úsalo solo en una máquina de pruebas y verifica la huella por un canal independiente.

Consulta [docs/architecture.md](docs/architecture.md) para el mapa de módulos y el flujo de configuración.

Para comprobar la configuración ejecuta `cargo test -p formic-core` y `cargo run -p formic-core`; ambos evalúan el Nickel embebido. Revisa `logs/certs/current.log` para el motivo de cualquier fallback y el resultado de la importación. El CLI externo `nickel export config/default.ncl` sigue siendo opcional para validación manual, no es requisito de Formic. El certificado de prueba no está habilitado por defecto.

Si Nickel no está disponible o la configuración no valida, el inspector registra el error y usa el modo de emergencia `alert_only`.

## Variables de entorno

La política está en `config/inspectors/environment/default.ncl`. Declara valores bajo `user` para el usuario actual o bajo `system` para las variables persistentes de Windows. Para exportar el inventario de ambos ámbitos a `config/inspectors/environment/snapshot.toml`, ejecuta `cargo run -p formic-core -- --dump-environment`. El comando solo lee el Registro y sobrescribe ese archivo; el TOML puede contener secretos y debe protegerse como tal. La ruta se cambia con `--environment-output FILE`.

Modos disponibles: `additive` agrega variables ausentes sin alterar valores existentes; `direct` asigna los valores declarados y, si se autoriza, elimina nombres no declarados; `subtractive` solo elimina nombres no declarados; `selective_delete` elimina solo los nombres enumerados en `delete_system` y `delete_user`. Toda eliminación está bloqueada salvo que también configures `allow_destructive = true`. El valor predeterminado es `additive` con borrado deshabilitado. Si omites estas opciones en una configuración existente, se aplican esos defaults seguros.

Para agregar otra variable, añade su nombre y valor al mapa correspondiente:

```nickel
{
    mode = "additive",
    allow_destructive = false,
    system = {},
    user = {
        PRUEBA = "ESTOESUNAPRUEBA",
        MI_VARIABLE = "mi valor",
    },
    delete_system = [],
    delete_user = [],
}
```

Ejecuta `cargo run -p formic-core -- --inspect-environment` para aplicarla y mantenerla. `subtractive` y `selective_delete` no borran nada mientras `allow_destructive` sea `false`. La lista de sistema necesita permisos elevados; el ámbito de usuario corresponde a la cuenta que ejecuta Formic. No guarda los valores en los logs, solo sus hashes. El inventario TOML sí guarda los valores en texto claro. Las variables ya cargadas en procesos existentes no se actualizan automáticamente.

## Licencia

Este proyecto se distribuye bajo la licencia **GNU General Public License v3.0 (GPLv3)**. 

### Excepción para archivos de configuración
Los archivos de configuración y reglas declarativas ubicados dentro del directorio `/config/` se distribuyen bajo la **Licencia MIT** para permitir que los usuarios y administradores adapten, reutilicen y compartan sus políticas libremente sin restricciones de Copyleft.
