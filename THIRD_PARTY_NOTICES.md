# Código de terceros

`vendor/broadcom-wps/broadcom_fingerprint.py`, `README.md` y `LICENSE.md` son copias sin cambios del repositorio https://github.com/qkaiser/broadcom-wps, commit `3cb3ef77d6b71e8441a51668c7e2b919608180f9`.

Copyright (c) 2026 Quentin Kaiser. Licencia MIT; texto completo en [`vendor/broadcom-wps/LICENSE.md`](vendor/broadcom-wps/LICENSE.md). [`UPSTREAM.json`](vendor/broadcom-wps/UPSTREAM.json) registra procedencia y hashes SHA-256. `.gitattributes` evita transformar los finales de línea de estos archivos.

POLTERHEIST importa la implementación y añade la selección/autorización por BSSID, inventario, informes y restricciones de transporte en `script.py`. No modifica el archivo upstream ni sus decisiones de detección. El bloqueo de su limpieza por desautenticación se declara expresamente en los informes y en el README.
