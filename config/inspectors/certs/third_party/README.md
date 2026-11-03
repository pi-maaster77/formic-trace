Coloca aquí certificados que quieras importar y enuméralos explícitamente en
`../default.ncl` como strings en `import_certificates`, por ejemplo
`"third_party/vendor-root.pem"`. Se admiten `.cer`, `.crt` y `.pem`, con un
certificado por archivo.

La importación requiere `allow_import = true`, `allow_destructive = true` y
permisos de escritura para `LocalMachine\Root`. Puede ejecutarse con
`mode = 'alert_only`: no hay purga automática, pero el import explícito sí
modifica el almacén. Se aceptan CAs vigentes y certificados no-CA solo si son
autofirmados y su firma verifica. El preset mantiene la importación apagada.

Verifica cada huella por un canal independiente. Un certificado instalado en
`LocalMachine\Root` modifica qué identidades confía Windows y puede habilitar
suplantación TLS.