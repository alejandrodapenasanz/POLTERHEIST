# H2/H3 — uso, evidencia y registro de validación

Fecha: **11-11-2026**. Entrega: H1 investigado/documentado, H2 implementado y H3 implementado para descubrimiento IP. Entorno ejecutado: **Windows, Python 3.13**. No se ha ejecutado Kali físico ni probado una TV con esta ampliación. Ningún resultado simulado se incluye en el inventario de producción.

Registro histórico de H2/H3. La tarea H4 posterior autorizó continuar el desarrollo: consultar [validación y límites de H4](H4_VALIDATION.md) para el estado actual y los nuevos comandos/menús. Las cifras y la puerta de revisión de este registro corresponden a aquella entrega.

## Entrega revisable

| Hito / backend | Implementación entregada | Límite explícito |
| --- | --- | --- |
| H1 | [Investigación y matrices](RESEARCH.md), [arquitectura](ARCHITECTURE.md), fuentes oficiales/repositorios y comparación GNOME Network Displays / FluxCast / MiracleCast. | Fotografía de documentación y mantenimiento, no prueba de interoperabilidad. |
| H2 | `hardware.py`: interfaces/PHY, IDs del chipset, driver, P2P, bandas/restricciones, combinaciones simultáneas, NM/supplicant, BlueZ/UUIDs locales, FFmpeg/GStreamer, PipeWire y portal/entorno gráfico. | Consultas de solo lectura. P2P/WFD o un encoder anunciado no verifican una sesión Miracast. |
| H3 A — LAN | Registro de adaptadores Cast, SSDP/UPnP/DLNA/DIAL y Bonjour AirPlay/RAOP; evidencia, alcance, autenticación y capacidades separadas. | Transporte IPv4. AirPlay/RAOP/DIAL son observaciones sin backend de reproducción nuevo. UPnP genérico puede ser un router u otro dispositivo. |
| H3 B — enrutado | IP, hostname fijado tras resolución y CIDR pequeño; selección de ruta, confirmación del ámbito, consultas Cast y SSDP unicast. | Máximo 16 hosts por defecto, configurable hasta 64. No escanea rangos de puertos. Fuera de la LAN seleccionada no habilita playback. |
| C/D/E — P2P, Miracast, Bluetooth discovery | Diseño e investigación, diagnóstico local de prerrequisitos. | Descubrimiento activo de radio y establecimiento de enlaces pendientes de H4/validación. |
| F/G — fabricantes/controladores | Matriz y contratos de extensión. | Pairing/APIs de fabricantes, Home Assistant y SmartThings pendientes de H5. |
| H6/H7 | Conservación del motor Cast/DLNA de imágenes/vídeo, sin nuevos transportes. | Audio, RTSP/RTP, captura, cache segura, correlación entre radios y selección inteligente pendientes. |

No se han instalado nuevas dependencias ni modificado NetworkManager, radios, firewall, rutas o configuración del sistema en esta ampliación. Se reutilizan las dependencias Python existentes. Las pruebas FFmpeg usan las herramientas ya disponibles en `.venv/ffmpeg-tools`, añadiéndolas únicamente al PATH del proceso de prueba.

## Ejecución en Kali

Desde el repositorio, con el entorno Python existente:

```bash
.venv/bin/python script.py --tv-diagnostics
.venv/bin/python script.py --tv-control
```

Si el setup anterior creó `.venv-linux`, usar `.venv-linux/bin/python`. El punto de entrada `POLTERHEIST.py` también acepta ambas opciones.

El diagnóstico no necesita conectividad LAN ni root. Consulta herramientas que ya existen y muestra `MISSING`, `ERROR`, `TIMEOUT`, `TRUNCATED` o `SKIPPED` por prueba. Permisos insuficientes quedan registrados; no ejecuta sudo ni instala herramientas. Tiene un presupuesto de 45 segundos, consultas de hasta 3 segundos y salida limitada a 128 KiB por comando, más el tiempo acotado de limpieza. Las propiedades D-Bus usan `--auto-start=no`; no se inicia captura, pairing ni búsqueda de radio. Los UUIDs BlueZ corresponden al adaptador local, no a perfiles verificados en una TV.

Guarda `reports/tv_control/hardware_<UTC>.json`. El código de salida es 0 al completar el diagnóstico Linux, aunque existan herramientas ausentes; se deben revisar los estados internos. En otras plataformas devuelve 1 y explica la limitación. Ctrl+C devuelve 130 desde la entrada CLI.

En TV Control:

1. Revisar las observaciones LAN. `COMPATIBLE BACKEND; SESSION UNTESTED` indica requisitos anunciados y backend disponible; no prueba pairing ni reproducción.
2. Usar **5 — Inspect capabilities** para consultar direcciones, fuente, evidencia, autenticación y detalles. La agrupación por IP es provisional, no una identidad física demostrada.
3. Usar **4 — Directed discovery** para una IP, hostname o CIDR autorizado, por ejemplo `192.168.50.20`, `tv.example` o `192.168.50.16/30`. Se muestran IP origen y destinos antes de pedir `y`. ENTER cancela.
4. Usar **7 — Configure discovery backends** para elegir `cast`, `upnp`, `airplay` durante la sesión. Cambia el motor de descubrimiento, sin cambiar servicios del sistema.
5. Cada búsqueda guarda `reports/tv_control/discovery_<UTC>.json`. Incluye tiempos, errores por backend, servicios y evidencia. `NO RESPONSE` no demuestra que el aparato esté apagado; puede filtrar ese protocolo.

Cada destino consulta Cast device-info y/o SSDP unicast según los backends habilitados. URLs de descripciones, SCPD y Application-URL deben permanecer en la IP literal aprobada; no se siguen redirecciones. Un destino fuera de la LAN permanece discovery-only porque no está verificada la ruta de retorno del servidor HTTP. Una actualización dirigida sin respuesta marca ausentes los dispositivos previos de ese ámbito, conservando los demás. Ctrl+C descarta trabajos pendientes y espera a que terminen las consultas acotadas ya iniciadas.

El descubrimiento multicast es activo. Una red distinta necesita una ruta autorizada que ya exista; el motor no crea túneles, reflectores ni redes P2P. Se conservan direcciones IPv6 en registros Bonjour recibidos por IPv4, pero no se descubren receptores exclusivamente IPv6. DNS-SD unicast, importación de leases y gateways autenticados están investigados, no implementados.

La reproducción conservada requiere **confirmación antes de cada inicio/cambio**, incluso con un solo dispositivo. AirPlay/RAOP/DIAL no aparecen como destinos reproducibles. RAOP no se etiqueta como vídeo. No se lanzan apps DIAL durante las búsquedas.

## Registro de pruebas automatizadas

Comandos ejecutados en Windows con la venv existente:

```powershell
.\.venv\Scripts\python.exe -m ruff check script.py POLTERHEIST.py tv_control tests
.\.venv\Scripts\python.exe -m ruff format --check script.py POLTERHEIST.py tv_control tests
$env:PATH = (Join-Path $PWD '.venv\ffmpeg-tools') + ';' + $env:PATH
.\.venv\Scripts\python.exe -m unittest discover -s tests
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe script.py --tv-diagnostics
```

| Comprobación | Resultado / evidencia |
| --- | --- |
| Suite completa | **227 pruebas: 226 correctas, 1 omitida por Nmap ausente.** Incluye las regresiones previas de LAN/Wi-Fi/portal/Windows y TV Control. |
| H2/H3 | **31 pruebas nuevas** en `tests/test_tv_engine.py`: parsers, herramientas ausentes, permisos, timeouts, diagnóstico no-Linux, scopes, DNS, cancelación, registro, Bonjour y DIAL. |
| Medios existentes | Conversión real de imágenes/vídeo con FFmpeg y ffprobe presentes; no omitidas. No supone prueba del decodificador de una TV. |
| Simulador de receptor | Test `test_simulated_ssdp_and_dial_http_receiver_end_to_end`: UDP y HTTP reales exclusivamente en loopback, nombre **SIMULATED DIAL RECEIVER**, ninguna app lanzada. La excepción de scope loopback existe solo en el fixture. |
| Limpieza/error HTTP | El simulador reprodujo un fallo con HTTP/1.0 al cerrar el socket tras cabeceras. Corregido conservando un descriptor para el deadline y cerrando explícitamente respuesta/conexión/descriptor. |
| Regresión de confirmación | Selección única y múltiple requieren confirmación antes de abrir archivos/iniciar sesiones. Rechazar el diálogo conserva las sesiones previas. |
| Calidad/dependencias | Ruff lint/formato y `pip check` correctos. |
| Diagnóstico real de este host | `hardware_20261111T182136852931Z.json`: `platform=win32`, `linux_supported=false`, sin sondeos Linux ficticios. Salida 1 esperada. Informe local ignorado por Git. |

Las primeras pruebas detectaron llamadas antiguas de test que iniciaban playback individual sin confirmar; se actualizaron al nuevo contrato. El fallo HTTP/1.0 se corrigió en producción y el simulador quedó como regresión. Los fixtures `iw`, BlueZ, mDNS y rutas están etiquetados como simulados; no certifican el driver real ni un receptor comercial.

## Validación física pendiente y siguiente revisión

En Kali Live físico, ejecutar el diagnóstico y revisar el PHY, driver, IDs del chipset, modos P2P, restricciones de frecuencia y coexistencia. Registrar errores de permisos o herramientas ausentes antes de proponer instalaciones. Probar descubrimiento con dispositivos propios despiertos, confirmar nombre/modelo/firmware y comparar cada protocolo anunciado. Para una subred enrutada, utilizar solo un destino explícito inicialmente y registrar respuestas/filtrado, sin asumir que una falta de respuesta demuestra ausencia.

Guardar estos datos en un registro local: fecha, Kali/kernel, interfaz/driver/chipset, modelo/firmware del receptor, topología autorizada, protocolos observados, acciones y resultado real. No incluir PIN, tokens ni credenciales en un informe compartido. Los reportes permanecen locales en `reports/`, ignorado por Git.

La reproducción Cast/DLNA previa tiene su [procedimiento manual](../TV_CONTROL.md#automated-and-manual-validation); requiere aceptación del receptor y confirmación de cada reproducción. La ampliación H3 no demuestra compatibilidad física adicional ni pairing AirPlay/Miracast.

**H4 y siguientes quedan pendientes de tu validación de esta entrega**, conforme a la instrucción final de la tarea. Cualquier instalación importante o cambio de configuración se preparará para revisión y requerirá autorización antes de ejecutarse.
