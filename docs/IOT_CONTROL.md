# IoT Scanning — uso y validación

Actualizado: **13-11-2026**. Destino: **Kali físico**, según indicación del propietario. Desarrollo y pruebas actuales: Windows 11 / Python 3.13. No se instalaron paquetes ni se modificaron servicios, firewall, rutas o políticas del host en esta ampliación.

## Menú

La opción principal **4** es **IoT Scanning — Discovery & Control**. Al entrar inicia automáticamente el análisis de la LAN seleccionada, los PHY Wi-Fi Direct elegibles y los adaptadores Bluetooth LE disponibles. Después muestra la tabla de dispositivos y este menú:

```text
[1] Connect to all detected devices
[2] Connect to selected devices (IDs separated by commas)
[3] Rescan all available transports
[4] Inspect device / connection options
[5] Media control (TVs / media receivers)
[6] Check selected device connectivity
[7] Hardware diagnostics
[8] Configure discovery backends
[9] Disconnect IoT connections
[10] Check MQTT session access
[11] Security observations
[0] Back
```

La opción **1** intenta conectar a los dispositivos actuales. La **2** acepta, por ejemplo, `1,3,5`: valida todos los IDs antes de iniciar ninguna conexión; rechaza duplicados, IDs desconocidos y observaciones caducadas. Cada dispositivo conserva su resultado aunque otro rechace la conexión. **9** cierra las conexiones IoT propias; volver al menú principal también las cierra. La reproducción multimedia tiene su propio control de sesiones.

El análisis inicial consulta los backends LAN habilitados y, después, P2P y BLE incluso si no hay LAN. No accede a otras redes Wi-Fi. Los permisos/servicios/hardware ausentes se muestran por fuente; Ctrl+C conserva los resultados parciales. Wi-Fi Direct mantiene las comprobaciones de coexistencia sin desconectar redes y BLE se pospone mientras haya sesiones GATT propias activas. Para volver a escanear BLE, desconectar con **9** y elegir **3**. IPv6 se conserva como metadatos de anuncios; su transporte sigue pendiente.

Ejemplo **SIMULATED**, no resultado de hardware real:

```text
ID  DEVICE               TYPE                       ADDRESS             CONNECT
1   SIMULATED light      Light                      192.0.2.20          LIMITED*
2   SIMULATED peripheral BLE peripheral (unknown)   AA:BB:CC:DD:EE:FF   YES*
3   SIMULATED P2P peer   Wi-Fi Direct peer          AA:BB:CC:DD:EE:00   NO
```

`YES*` significa que hay un conector implementado, pendiente de aceptación real. `LIMITED*` permite comprobar un handshake MQTT o un socket TCP y después lo cierra; no acredita control autenticado. `NO` indica conector no implementado u observación caducada. La tabla explica el motivo en cada fila. Una luz HomeKit con TCP accesible sigue necesitando pairing y un controlador HomeKit, aunque la comprobación TCP funcione.

La clasificación nueva usa categorías/servicios anunciados, no palabras como “TV”, “camera” o “plug” en el nombre. Se conservan los metadatos e inferencias históricas del backend Cast. Un servidor web puede ser un ordenador y queda con tipo desconocido. Un broker MQTT no revela automáticamente sus sensores. Agrupar servicios por IP no prueba identidad física.

## Cobertura implementada

| Backend | Evidencia y alcance |
| --- | --- |
| `cast`, `upnp`, `airplay` | Protocolos H3 anteriores; Cast/DLNA conservan reproducción, AirPlay/RAOP/DIAL son discovery. Se clasifican tipos UPnP conocidos por URN. |
| `iot_mdns` | 16 servicios: HomeKit TCP/UDP; Matter operativo, commissionable y commissioner; Shelly; ESPHome; Home Assistant; IPP/IPPS/LPD/raw printing; MQTT/MQTT TLS; HTTP/HTTPS. No todos los dispositivos anuncian DNS-SD. |
| `onvif` | Una consulta WS-Discovery; ProbeMatches correlacionado, QName/scopes ONVIF y XAddr del IP respondiente. Sin login ni apertura de cámara. Rechaza DTD, URLs ajenas, credenciales y puertos inválidos. |
| `coap` | NON GET `/.well-known/core`; token correlacionado y formato CoRE. Máximo 16 KiB por respuesta. No sigue enlaces ni actúa sobre recursos. Bloques parciales quedan marcados; no se descarga el resto ni se implementa DTLS/OSCORE. |
| Wi-Fi Direct | Backend Linux NM/supplicant; P2P/WFD H4. Se intenta una interfaz elegible por PHY durante el análisis inicial. Conexión Miracast pendiente. |
| Bluetooth LE | Bleak 3.1.0, escaneo finito por adaptador Linux o adaptador predeterminado Windows. Dirección, RSSI, manufacturer data y UUIDs anunciados. Las direcciones privadas pueden rotar; no se fusionan por nombre. |

El análisis consulta las fuentes soportadas/habilitadas del ámbito. No cubre todos los equipos silenciosos, cloud-only, Zigbee, Thread, Z-Wave, RF arbitraria o VLANs aisladas. El orden de validación en Kali y desarrollo posterior está en [ROADMAP.md](../ROADMAP.md).

## Conectividad y seguridad

**1/2 — Conectar todos o IDs** selecciona el conector disponible por dispositivo. BLE conserva una conexión GATT y enumera UUIDs de servicios; no solicita pairing ni lee/escribe características protegidas. Cast conserva una sesión sin reproducir; DLNA verifica el protocolo y muestra `PROTOCOL READY`, pues no es una sesión persistente equivalente a GATT. MQTT devuelve `SESSION VERIFIED / CLOSED` cuando completa el handshake y TCP devuelve `TCP ONLY / CLOSED` si alcanza algún servicio. Un fallo de autenticación o permiso permanece como fallo. Esos estados y su hora se exportan en `iot_connection`.

**6 — Check connectivity** prueba como máximo cuatro pares IP/puerto TCP anunciados en la LAN, dos segundos por conexión y un máximo compartido de ocho (o `connect_timeout` si es menor). No envía payload de aplicación. UDP/P2P y Matter no se prueban como TCP. `TCP REACHABLE` no acredita credenciales ni controlador.

**10 — MQTT** requiere seleccionar dispositivo y endpoint. Envía CONNECT MQTT 3.1.1 con sesión limpia, ID aleatorio propio y sin credenciales. Registra CONNACK y, si se acepta, envía DISCONNECT y cierra. Nunca publica, suscribe ni configura Last Will. Dura como máximo cinco segundos o `connect_timeout`. MQTT TLS verifica el certificado contra el IP seleccionado usando la confianza del sistema: un certificado solo para hostname puede fallar; no se omite la validación ni se reintenta sin TLS. MQTT 5, credenciales, CA propia y ACL de tópicos quedan pendientes.

**11 — Security observations** resume HTTP sin TLS anunciado y, si se probó expresamente, aceptación anónima MQTT. Son exposiciones, no CVEs confirmadas. CONNECT aceptado no acredita permisos de lectura/publicación; ausencia de hallazgos no acredita seguridad. No se ejecutan exploits. F4/F5 del roadmap definen evaluación y reproducción por modelo/firmware y objetivo de laboratorio.

Cast/DLNA continúan en **5 — Media control**, seleccionando contenido y confirmando reproducción. Al entrar se cierran las conexiones IoT previas para que el reproductor gestione sus sesiones. Los demás protocolos muestran sus requisitos y controlador pendiente. Las credenciales no se consideran disponibles por recibir un anuncio.

## Configuración y reportes

Se conservan `config/tv_control.json`, el paquete `tv_control/`, logs e IDs. Por defecto:

```json
{"discovery_backends": ["cast", "upnp", "airplay", "iot_mdns", "onvif", "coap"]}
```

Las listas personalizadas LAN no se sobrescriben: añadir backends mediante **8** o editando la configuración local. Se aplican timeouts y `max_devices` por backend/adaptador (32 por defecto), por lo que las redes grandes pueden limitar resultados. `ble_timeout` vale ocho segundos por adaptador; `connect_timeout` limita conexiones. El error de un backend no descarta los demás.

`reports/tv_control/discovery_*.json` incluye endpoints, `iot_summary`, resultados por transporte, conexiones IoT, comprobaciones TCP/MQTT, observaciones de seguridad, errores y timestamps. Reports/configuración local/medios están ignorados por Git. Solo se guardan claves TXT permitidas.

## Comandos

En Kali, desde la raíz del repositorio:

```bash
bash setup.sh                              # Crear/reutilizar venv, instalar requirements y ejecutar
bash setup.sh --install-system --no-run    # Incluir APT expresamente y preparar sin ejecutar
bash setup.sh --run-only -- --iot-scan     # Ejecutar sin instalar de nuevo
bash setup.sh --run-only -- --tv-diagnostics
```

`setup.sh` debe ejecutarse como usuario normal, no con sudo. Usa el Python de la venv directamente: activar y desactivar el entorno es opcional. Reutiliza `venv`, `.venv`, `.venv-linux` o `venv-linux` si contienen un entorno Linux; preserva un entorno Windows. Si falta `python3-venv`, informa del comando de reparación o de `--install-system`. Solo esa opción instala paquetes APT con sudo; pip siempre se ejecuta dentro del entorno. Para tareas que requieran root, el script imprime el comando con la ruta exacta de su Python.

Para las pruebas, usar el intérprete que indique setup, por ejemplo `venv/bin/python -m unittest discover -s tests`. En Windows usar `.venv\Scripts\python.exe`; `setup.sh` está destinado a Linux. `--tv-control` sigue siendo alias de `--iot-scan`.

BLE añade `bleak==3.1.0`: Linux con BlueZ >= 5.55, D-Bus disponible y permisos de usuario, o Windows 11 compatible con WinRT Bluetooth. Bleak no está instalado en el host Windows de esta entrega; sus pruebas usan un transporte SIMULATED. Los dispositivos/radios ausentes o desactivados se notifican, no se reconfiguran automáticamente. Las pruebas físicas de BLE, GATT y P2P siguen pendientes.

## Contratos consultados

- [Shelly mDNS](https://shelly-api-docs.shelly.cloud/gen2/General/mDNS/) y [ESPHome mDNS](https://developers.esphome.io/architecture/components/mdns/).
- [Categorías HAP](https://github.com/ikalchev/HAP-python/blob/master/pyhap/const.py), como indicios del tipo anunciado.
- [Matter Core](https://csa-iot.org/wp-content/uploads/2022/11/22-27349-001_Matter-1.0-Core-Specification.pdf), DNS-SD; sin commissioning implementado.
- [ONVIF Core](https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf), WS-Discovery.
- [MQTT 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html), CONNECT/CONNACK/DISCONNECT.
- [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252) y [RFC 6690](https://www.rfc-editor.org/rfc/rfc6690), CoAP/CoRE.
- [IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml), servicios de impresión y MQTT.
- [Bleak Scanner](https://bleak.readthedocs.io/en/latest/api/scanner.html), [Client](https://bleak.readthedocs.io/en/latest/api/client.html), [BlueZ](https://bleak.readthedocs.io/en/latest/backends/linux.html) y [versión fijada](https://pypi.org/project/bleak/3.1.0/).

## Pruebas en Windows — 12-11-2026

- **61 pruebas IoT correctas**. Incluyen sockets reales contra simuladores loopback TCP, ONVIF, CoAP y MQTT; clasificación, límites, limpieza, rechazo, TLS fallido sin fallback, entradas malformadas y menús. Las nuevas pruebas verifican escaneo al entrar, tabla, selección por IDs/todos, error parcial, BLE/GATT y cierre del bucle async. DNS-SD y BLE unitarios usan transporte SIMULATED; no validan la DLL ni hardware reales.
- **9 pruebas de `setup.sh` correctas**, ejecutadas mediante Git Bash con uname/id/python/pip/sudo simulados. Cubren creación, reutilización, entornos Windows preservados, rutas con espacios, ejecución desde otra carpeta, APT explícito y errores de pip/venv. No instalan paquetes. `bash -n setup.sh` también correcto.
- **Suite completa: 354 pruebas, 347 correctas, seis errores y una omitida**, en 18,660 segundos. Los seis errores proceden de Windows Application Control al cargar una DLL de zeroconf, afectando también a Cast/AirPlay existentes. Nmap no instalado explica la omisión. Evidencia: `reports/tv_control/iot_survey_regression_windows.txt`.
- La primera ejecución detectó que ONVIF aceptaba puerto cero como puerto por defecto: corregido y con regresión. No se cambiaron políticas ni reinstalaron paquetes para ocultar el problema de DLL.
- Cierre del 13-11: Ruff correcto, **46 archivos con formato correcto**, **38 referencias locales comprobadas sin errores**, `git diff --check` y sintaxis Bash correctos. Tras reforzar la comprobación de versión del Python reutilizado se repitieron las nueve pruebas del instalador: correctas. La regresión de navegación simula el escaneo; entrar realmente en `--iot-scan` ahora sí inicia búsqueda.

La suite **no está completamente verde** en este host. No se ha escaneado una red física ni validado receptores/radios reales en esta ampliación. El roadmap mantiene abiertas las pruebas físicas y la resolución autorizada del entorno de dependencias.
