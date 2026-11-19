# POLTERHEIST — orden de trabajo

Actualizado: **19-11-2026**. Entorno objetivo: **Kali en hardware físico**.

**Primero completar las cuatro prioridades inmediatas, en el orden indicado; después validar el conjunto en Kali y continuar con el resto del desarrollo. Si una comprobación falla, reproducir el fallo, corregirlo y repetirla antes de avanzar.** Una prueba en Windows, un simulador o CI no sustituye la validación física.

## 1. Prioridades inmediatas

Estas tareas van antes que cualquier otra del roadmap:

**Estado (19-11-2026): los cuatro puntos están implementados.** Logs y PayloadTV
comprobados desde Windows; imagen y vídeo programados validados en una Xiaomi
MiTV-MSSP2 mediante Cast HTML, con confirmación visual del usuario. Instalador y
diagnóstico de hardware siguen pendientes de validación física en Kali.
La comprobación automática incluye pruebas del instalador con herramientas simuladas,
hardware ausente/desconocido, logs, programación de imagen/vídeo en Chromium sin servidor
y compilación/firma real de APK con programación. Uso y límites:
[README](README.md) y [PayloadTV](docs/TV_PAYLOAD.md#scheduled-playback).
Pruebas físicas y correcciones: [resultados TV/Windows](docs/VALIDATION_2026-11-19.md).
Los informes detallados se conservan localmente en `reports/priority-1-4-validation.md`
y `reports/tv_validation_20261119/`.

1. [ ] **Corregir `setup.sh`:** asegurar que la instalación del sistema comienza con `sudo apt update` (o `apt update` si ya se ejecuta como root), antes de instalar dependencias. Reproducir y corregir los errores de permisos, incluidos los del repositorio y el venv; verificar tanto `bash setup.sh` como `sudo bash setup.sh` y la reinstalación.
2. [ ] **Comprobar hardware al abrir POLTERHEIST:** ejecutar automáticamente un chequeo de los dispositivos y capacidades del PC antes de mostrar el menú. Marcar en rojo las opciones que el equipo no puede ejecutar e indicar el motivo; distinguir hardware ausente o incompatible de permisos o dependencias pendientes.
3. [x] **Crear un sistema de logs:** registros persistentes de arranque, diagnóstico, acciones y errores, con fecha/hora, nivel, módulo, sesión, trazas y rotación. Comprobados desde Windows durante las pruebas reales de TV.
4. [x] **Programar imagen/vídeo en PayloadTV:** hora de inicio, repetición cada X minutos, próxima ejecución y cancelación. Verificados imagen a hora fija, imagen/vídeo repetidos y cancelación en Xiaomi mediante Cast HTML, con el servidor de contenido cerrado. Ejecución APK y otros fabricantes pendientes.

## 2. Validar y corregir en Kali

Después de completar la fase 1, ejecutar en este orden, con redes y dispositivos propios o autorizados:

Avance complementario desde Windows (19-11-2026): detección de la TV, reproducción
Cast, pausa/reanudación/parada, repetición, portal local, diagnóstico y logs comprobados.
Corregidos la reutilización de una sesión DashCast obsoleta y el tiempo de arranque
del receptor de medios. Esto no cierra las comprobaciones exclusivas de Kali/DLNA.

1. [ ] **Instalación desde cero:** probar `bash setup.sh` y `sudo bash setup.sh`; verificar dependencias APT, todo `requirements.txt`, creación/activación del venv, permisos del usuario y arranque de `python3 POLTERHEIST.py`. Repetir la instalación, probar una terminal nueva y conservar cualquier venv de Windows.
2. [ ] **Entorno y regresión:** ejecutar `--check`, `--tv-diagnostics`, `python -m pip check`, la suite completa de unittest, Ruff y `bash -n setup.sh` usando el venv. Ejecutar las pruebas exclusivas de Linux, Nmap/FFmpeg y el portal en namespaces aislados. Verificar también las importaciones de zeroconf/PyChromecast que fallaban por una DLL bloqueada en Windows; resolver fallos y justificar las omisiones.
3. [ ] **Interfaz y perfil:** recorrer todos los menús, guardar/recuperar el perfil y comprobar el fantasma animado, escritura/borrado, redimensionado, modo sin animación, Ctrl+C, EOF y regreso desde cada función.
4. [ ] **LAN Recon:** comprobar descubrimiento, identificación, selección de objetivos, escaneo, cancelación y reportes con equipos reales.
5. [ ] **Wi-Fi/WPS:** comprobar adaptadores y permisos, red conectada, selección SSID/BSSID, captura e inyección con hardware compatible, resultados y restauración de modo/canal/conexión tras éxito, error y Ctrl+C.
6. [ ] **Portal cautivo:** probar vista local, creación de AP y router/AP externo; verificar interfaces alternativas, DHCP/DNS/NAT, aceptación/caducidad del acceso y restauración de red/firewall tras cierre o fallo.
7. [ ] **IoT por IP:** validar descubrimiento automático y dirigido de Cast, DLNA/UPnP/DIAL, AirPlay/RAOP, DNS-SD, ONVIF y CoAP; comprobar IDs, resultados parciales, selección individual/todos, conexiones TCP/MQTT y reportes, sin confundir discovery con control.
8. [ ] **Wi-Fi Direct y BLE:** validar radios/PHY reales, backends NetworkManager y supplicant, anuncios WFD, coexistencia con la LAN, permisos, búsqueda/cancelación, GATT, desconexión y nuevo escaneo; repetir con varios adaptadores. Comprobar la preparación Miracast existente, sin dar por implementada su conexión.
9. [ ] **Cast/DLNA y medios:** probar imagen/vídeo, conversión y caché, repetición, pausa, reanudación, parada, varios receptores, pérdida de conexión y cambios externos de contenido; comprobar cierre de sesiones, servidor HTTP y procesos.
10. [ ] **Cerrar validación:** repetir la regresión tras las correcciones y confirmar que no quedan fallos ni comprobaciones de Kali pendientes antes de pasar a la fase 3.

Si falta hardware o acceso, registrar el bloqueo y continuar con otras comprobaciones de esta fase. No marcarlo como aprobado ni sustituirlo por una simulación.

## 3. Continuar el desarrollo

Solo después de cerrar la fase 2, seguir este orden:

1. [ ] **Cobertura IP:** IPv6 y múltiples interfaces, redes segmentadas, evidencia ARP/NDP/DHCP y ampliación de CoAP/OCF, IPP/eSCL y protocolos adicionales según los equipos disponibles.
2. [ ] **Radio y ecosistemas:** ampliar BLE/GATT, autenticación y reconexión; añadir Zigbee, Thread/Matter, Z-Wave y RF/IR/SDR con hardware compatible, inventario y capturas documentadas.
3. [ ] **Conexiones autenticadas:** MQTT 5/TLS/ACL, HTTP y APIs de fabricantes, Shelly/ESPHome, Home Assistant/bridges, HomeKit/Matter y ONVIF/RTSP; separar capacidades, credenciales y acciones por dispositivo.
4. [ ] **Miracast real:** elegir un stack mantenido, implementar pairing/conexión y transmisión de imagen/audio, y verificar recepción y desconexión en un equipo físico.
5. [ ] **Medios e inventario:** ampliar audio, RTSP/RTP y captura; mejorar correlación de identidades, caché de capacidades y selección de transporte.
6. [ ] **Evaluación de seguridad:** hallazgos con evidencia, modelo/firmware, referencias y remediación; distinguir exposición de vulnerabilidad y añadir comprobaciones acotadas de fallos conocidos en el laboratorio.
7. [ ] **Validar cada ampliación:** añadir regresiones pertinentes, probar en Kali con el hardware correspondiente y actualizar guías/reportes antes de darla por terminada.

## Seguimiento

Marcar una tarea solo con evidencia. Guardar en `reports/` fecha, Kali/kernel, hardware/firmware, comandos, resultado, correcciones y bloqueos; mantener aquí únicamente el estado y el siguiente trabajo.

Guías operativas: [README](README.md), [IoT](docs/IOT_CONTROL.md) y [TV/medios](docs/TV_CONTROL.md).
