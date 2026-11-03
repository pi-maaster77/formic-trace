Para mapear este ecosistema masivo y saber exactamente por dónde empezar a tirar del hilo sin romper la VM en el primer intento, vamos a dividirlo en una **matriz de dependencias y criticidad**.

Identificaremos qué subsistemas son **islas independientes** (perfectos para arrancar con el ciclo de desarrollo) y cuáles son **hubs centralizados** que dependen de múltiples capas.

---

### 1. Matriz de Interacciones y Dependencias de Formic

| Subsistema / Módulo | Tipo | Depende de (Requiere a...) | Es requerido por (Alimenta a...) | Nivel de Riesgo (si aplicás Default-Deny) |
| :--- | :--- | :--- | :--- | :--- |
| **`inspectors/certs`** | **Isla (Leaf)** | Ninguno (CryptoAPI nativa) | `policies/processes` (para WinVerifyTrust) | **Bajo** (Seguro para empezar) |
| **`inspectors/environment`** | **Isla (Leaf)** | Ninguno (Registry básico) | `policies/processes` (Path de ejecución) | **Bajo** |
| **`inspectors/hardware/...`**<br>*(BitLocker, Printeando, USB)* | **Isla (Leaf)** | Ninguno (WMI / SetupAPI) | Ninguno (Principalmente inventario) | **Bajo** |
| **`inspectors/identity/...`**<br>*(Users, Groups, Credentials)* | **Isla (Leaf)** | Ninguno (NetAPI32 / SAM) | `policies/tokens` (Contexto de seguridad) | **Medio** (Si bloqueás SAM, rompes logon) |
| **`inspectors/system_features`** | **Isla (Leaf)** | Ninguno (DISM / IP Helper) | Ninguno (Configuración estática) | **Bajo** |
| **`inspectors/registry`** | **Hub Base** | Ninguno (Advapi32 base) | *Casi todo el sistema* | **Alto** (El registro es el sistema) |
| **`inspectors/filesystem`** | **Hub Base** | Ninguno (Win32 CreateFile) | *Casi todo el sistema* | **Alto** (Bloquear FS cuelga el kernel) |
| **`inspectors/services`** | **Compuesto** | `filesystem`, `registry` | `policies/processes` | **Medio-Alto** (Servicios vitales) |
| **`inspectors/tasks`** | **Compuesto** | `filesystem`, `registry` | Ninguno (Persistencia común) | **Medio** |
| **`policies/network`** | **Intercepción** | Ninguno (WFP API / Sockets) | Ninguno (Filtrado de red) | **Medio** (Te podés quedar sin internet) |
| **`policies/tokens`** | **Intercepción** | `identity` | `policies/processes` | **Alto** (Control de privilegios) |
| **`policies/lsa`** | **Intercepción** | Ninguno (LSA Policy API) | Ninguno (Seguridad global UAC) | **Alto** |
| **`policies/kernel_drivers`** | **Intercepción** | Ninguno (NtLoadDriver) | `policies/processes` | **Crítico** (BSOD asegurado si fallás) |
| **`policies/wmi`** | **Intercepción** | Ninguno (COM / WBEM) | Ninguno (Persistencia fileless) | **Bajo** |
| **`policies/sessions`** | **Intercepción** | Ninguno (WTS API) | Ninguno (Control de RDP) | **Bajo** |
| **`policies/processes`** | **Gran Hub Central** | **Filesystem, Certs, Tokens, Registry** | El motor entero de enforcement | **Crítico** (Corazón de Formic) |


---

### 2. ¿Por dónde empezar? (El Orden de Ataque Recomendado)

Siguiendo tu ciclo de desarrollo (*Observar $\rightarrow$ Romper VM $\rightarrow$ Revivir con Nickel*), te conviene empezar desde las esquinas más inofensivas hacia el centro del motor:

#### Fase A: Las Islas Inofensivas (Primeros Pasos en Rust)

Construí y probá los módulos que no dependen de nada. No van a romper la VM de Windows, lo que te permite validar que tus estructuras de datos y llamadas FFI a la WinAPI funcionan correctamente:

1. **`inspectors/certs`**: Implementar la lectura del almacén raíz de certificados con la CryptoAPI.
2. **`inspectors/environment`**: Leer variables de entorno y el `%PATH%`.
3. **`inspectors/hardware/usb_devices`**: Listar dispositivos conectados vía SetupAPI.

#### Fase B: Los Cimientos de Almacenamiento (Infraestructura)

Una vez que domines las llamadas básicas, implementá los motores de lectura de los dos grandes pilares de Windows:
4. **`inspectors/registry`**: Crear el wrapper genérico para leer claves y valores de `HKLM` y `HKCU`.
5. **`inspectors/filesystem`**: Implementar lectura de atributos y cálculo rápido de hashes SHA256 para archivos.

#### Fase C: Los Módulos Compuestos (Primeros con Dependencias)

Aquí empezás a cruzar datos (por ejemplo, un servicio que lee su binario en el filesystem):
6. **`inspectors/services`**: Consultar el SCM y verificar contra el filesystem dónde apunta el ejecutable del servicio.
7. **`inspectors/tasks`**: Leer tareas programadas combinando la ruta en `C:\Windows\System32\Tasks` y la API COM.

#### Fase D: El Apocalipsis Controlado (Políticas e Interceptación)

Cuando ya tengas visibilidad de todo lo anterior, pasás a las políticas de seguridad y control activo:
8. **`policies/network`**: Monitorear sockets y aplicar reglas WFP.
9. **`policies/tokens`**: Filtrar privilegios peligrosos de los procesos.
10. **`policies/processes` (El Boss Final)**: Unir el calculador de hashes, la validación de certificados (`certs`), el control de archivos (`filesystem`) y los eventos del kernel para gobernar el nacimiento de cada proceso en la VM.