Coloca aquí los certificados CA que quieras importar y enuméralos explícitamente
en `../default.ncl` bajo `import_certificates`. Se admiten archivos `.cer`, `.crt`
y `.pem` con un certificado por archivo. La importación al almacén
`LocalMachine\Root` requiere `allow_import = true` y privilegios adecuados.

No copies aquí certificados sin verificar su identidad y huella por un canal
independiente. La importación cambia qué emisores confía Windows.