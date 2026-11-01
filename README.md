# POLTERHEIST

Herramienta de inventario y evaluación de redes propias o autorizadas: **LAN en Kali Linux y Wi-Fi/WPS en Linux y Windows**, con interfaz de terminal verde, arte ASCII y tres entradas:

```text
[0] WHO AM I?
[1] LAN RECON
[2] WIRELESS RECON

[q] EXIT
```

La aplicación está en **`script.py`**, organizada por funciones. Se ha evolucionado el código LAN existente; `POLTERHEIST.py` sigue funcionando como entrada compatible. El detector externo permanece separado en `vendor/` para conservar su código original, licencia y procedencia.

## Instalación en Kali

Arranca Kali (por ejemplo, Kali Live desde USB), **conéctate a tu Wi-Fi** y abre el repositorio. Se necesita Python **3.11 o posterior**:

```bash
git clone https://github.com/alejandrodapenasanz/POLTERHEIST.git
cd POLTERHEIST
python3 script.py --setup
.venv/bin/python script.py --check
.venv/bin/python script.py --wireless
```

`script.py` detecta Windows o Linux y lee `/etc/os-release` para identificar Kali. `--setup` instala las herramientas con APT, añade `firmware-mediatek` en Kali y crea un entorno virtual con Scapy 2.7.0, sin modificar el Python del sistema. Si copiaste una `.venv` de Windows a Linux, conserva esa carpeta y crea `.venv-linux`; utiliza la ruta que imprime al terminar. La instalación necesita Internet. Si Kali no reconoce la tarjeta después de actualizar su firmware, puede ser necesario reiniciar.

El flujo inalámbrico solicita `sudo` automáticamente cuando lo necesita, conservando el intérprete del entorno virtual. Obtiene el **SSID conectado**, descubre sus BSSID, ejecuta el fingerprint original y **después muestra una sola tabla `WIRELESS RESULTS`**, con `ASSESSMENT` en la columna derecha. Las otras redes observadas quedan en `NOT_TESTED`. No hay selección posterior de ID ni listado duplicado de BSSID.

La preparación de la radio y su restauración son automáticas. Si utiliza el adaptador de tu conexión, esta se pausará durante cada prueba. Se prioriza otra radio compatible desconectada cuando existe. Menú y perfil pueden abrirse con `.venv/bin/python script.py`; LAN requiere root.

Para indicar otra red propia/autorizada o limitar el análisis a un BSSID:

```bash
.venv/bin/python script.py --wireless --ssid 'Mi Wi-Fi'
.venv/bin/python script.py --wireless --ssid 'Mi Wi-Fi' --bssid aa:bb:cc:dd:ee:ff
```

Sin conexión ni `--ssid`, se muestra el descubrimiento sin ejecutar pruebas activas. Un SSID compartido por varios BSSID obtiene un resultado independiente para cada uno; no se propaga un positivo entre radios.

El flujo LAN requiere Linux. El descubrimiento Wi-Fi y WPS dispone de un backend nativo de Windows; no necesita `iw`, WSL, Nmap ni `arp-scan`.

## Wi-Fi y WPS en Windows

Desde PowerShell, con Python 3.11 o posterior:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe script.py --check
.\.venv\Scripts\python.exe script.py --wpscan
```

`--wpscan`, `--wireless` y `--fingerprint` ejecutan el flujo automático sobre el SSID conectado; también puedes usar `[2]` en el menú. `--ssid` permite indicar explícitamente el alcance autorizado. Aquí `wpscan` se refiere a WPS de Wi-Fi.

### Comprobar vulnerabilidad con el fingerprint

```powershell
.\.venv\Scripts\python.exe script.py --fingerprint
```

La aplicación utiliza la red conectada como alcance autorizado por defecto, prepara una radio compatible y evalúa secuencialmente sus BSSID observados. `--bssid` permite limitarla a una radio concreta. La ausencia de respuesta o la falta de soporte del controlador no se convierten en un resultado negativo.

Se muestra **una sola tabla al terminar las evaluaciones**, también al redirigir la salida a un archivo. Cada fila conserva literalmente el resultado de `broadcom_fingerprint.py` de [`qkaiser/broadcom-wps`](https://github.com/qkaiser/broadcom-wps#assessments):

| ASSESSMENT | Significado |
| --- | --- |
| `LIKELY_VULNERABLE` | Rechazo compatible con Broadcom WPS Monitor: probablemente vulnerable. |
| `PATCHED_HOSTAPD` | ACK compatible con hostapd y evidencia Broadcom en el anuncio: equipo Broadcom con hostapd. |
| `NO_BROADCOM_FINGERPRINT` | ACK compatible con hostapd sin evidencia Broadcom en el anuncio. |
| `INCONCLUSIVE` | El detector no obtuvo una respuesta clasificable; consulta su advertencia. |
| `NOT_TESTED` | Estado de POLTERHEIST: la prueba no se ejecutó; se muestra el motivo. |
| `ERROR` | Estado de POLTERHEIST: fallo de ejecución o evidencia que no corresponde al objetivo. |

Las redes fuera del alcance o cuya prueba no pudo iniciarse siguen en `NOT_TESTED`. Los resultados `PATCHED_HOSTAPD` y `NO_BROADCOM_FINGERPRINT` se mantienen separados en pantalla y en los informes. Solo `LIKELY_VULNERABLE` es un hallazgo positivo; no confirma explotación ni RCE. `INCONCLUSIVE` no significa que el equipo sea seguro.

El detalle —explicación, implementación estimada, respuestas, estado y advertencias— se guarda en `reports/wireless/<scan_id>/targets/<BSSID_sin_dos_puntos>/fingerprint.json`. El `report.json` general contiene todos los resultados y sus rutas. Para un único objetivo también se conserva `fingerprint.json` en la carpeta principal. Los archivos originales `upstream_result.json` y PCAP se conservan por BSSID. Un positivo o negativo requiere una salida original correspondiente al SSID/BSSID; el fabricante, la presencia de WPS o la seguridad WPA no bastan.

Si falta Npcap en Windows, aparece `NOT_TESTED` con el motivo. Añadir el comando no sustituye los requisitos de captura/inyección que se detallan a continuación.

El listado utiliza la **API Native Wi-Fi de Windows** (`wlanapi.dll`). Obtiene BSSID, SSID, frecuencia/canal, RSSI en dBm, calidad y elementos de información WPS/RSN/WPA proporcionados por el controlador. No depende del idioma de `netsh`. WPS solo aparece como `Detected` si existe un anuncio WPS; descubrirlo no significa que el AP sea vulnerable. Se conservan también los bytes originales del listado BSS y los IE.

Este descubrimiento funciona con una interfaz Wi-Fi normal, incluso conectada. Solicita una actualización ordinaria a Windows, que puede emitir sondas de descubrimiento, y espera la notificación de finalización. Si Windows no la confirma, el informe indica que los datos pueden proceder de caché. No cambia el modo de la tarjeta ni desconecta la conexión.

Si aparece **error 5 / acceso denegado**, permite el acceso a **Ubicación** en Configuración → Privacidad y seguridad → Ubicación para la aplicación/terminal. Windows protege con ese permiso la lectura de BSSID. Si aparece **error 1062**, revisa el servicio **Configuración automática de WLAN (`WlanSvc`)**. [Documentación de Microsoft](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes).

### Prueba WPS activa con Npcap

Para ejecutar el detector, además del listado, necesitas:

- [Npcap](https://npcap.com/#download) instalado con la opción **Support raw 802.11 traffic (and monitor mode) for wireless adapters**. No se incluye ni instala automáticamente este controlador.
- Permisos de administrador: si encuentra un adaptador compatible y faltan permisos, POLTERHEIST solicita la elevación normal de **UAC** y abre su ventana de trabajo. Windows requiere que el usuario acepte ese diálogo.
- Un adaptador/controlador que permita captura monitor e inyección 802.11. La capacidad de mostrar redes no demuestra que permita inyectar.
- El programa configura el adaptador automáticamente. Si utiliza uno conectado, esa conexión se pausará durante la prueba. Un adaptador dedicado permite conservar la conexión principal.

El transporte Windows implementado admite la **prueba activa en 2.4 GHz**. El listado puede mostrar otras bandas; la prueba activa de 5 GHz permanece en el backend Linux y el detector no admite 6 GHz. Npcap debe entregar cabeceras Radiotap y el AP seleccionado debe observarse en la frecuencia exacta antes de transmitir. Un fallo de recepción/inyección produce `ERROR` o `INCONCLUSIVE`, nunca un negativo por suposición.

La preparación automática guarda el modo y el nombre del perfil de conexión anterior, activa `monitor`, fija el canal seleccionado y comprueba el resultado. Al salir —también por error o Ctrl+C— restaura `managed` y solicita la reconexión al perfil anterior, verificando que Windows la confirme. Si el adaptador ya estaba en monitor, restaura su frecuencia original. No lee contraseñas. `radio_setup.json` registra el estado y cualquier fallo de restauración, que también se muestra en pantalla. Un cierre forzado del proceso o del sistema puede impedir ejecutar la restauración.

**Un controlador que solo anuncia `managed` no permite este fingerprint en Windows**, aunque Npcap esté instalado con soporte 802.11. El programa informa de ese impedimento y deja `NOT_TESTED`, sin desconectar el adaptador ni pedir que lo prepares manualmente. `--check` muestra los modos disponibles. Para consultar el controlador directamente:

```powershell
$wifiGuid = 'GUID-DEL-ADAPTADOR'
$wlanHelper = "$env:SystemRoot\System32\Npcap\WlanHelper.exe"
& $wlanHelper $wifiGuid modes
```

Solo como recuperación si el proceso se cerró por la fuerza, puedes devolver el adaptador al modo normal desde PowerShell con permisos de administrador:

```powershell
& $wlanHelper $wifiGuid mode managed
```

La prueba se limita a los BSSID del alcance autorizado y bloquea desautenticación/desasociación. Se adapta únicamente la captura/transmisión y el control de canal del detector original a Scapy/Npcap; su lógica de detección y los archivos upstream no se modifican. Si el controlador no admite este flujo, utiliza un adaptador compatible en Kali. [Requisitos de Npcap](https://npcap.com/guide/npcap-devguide.html#npcap-feature-dot11).

## Perfil

WHO AM I permite editar nombre/alias, especialización, biografía, GitHub, LinkedIn, web y contacto. `config/profile.json` se crea con campos vacíos al abrirlo por primera vez. También se puede copiar y editar `config/profile.example.json`. No incluye información personal inventada. El perfil local se excluye de Git.

## LAN RECON

- **Ghost Mode:** escaneo completo con `-T2 --max-rate 50`. **Hunter Mode:** escaneo completo con `-T3`. Ambos generan tráfico y son detectables.
- Descubrimiento combinado ARP/Nmap, IPs sin duplicados, MAC, fuentes y evidencias de fabricante. Identificación de máquina local y puerta de enlace.
- Identificación preliminar mediante servicios y huellas de SO. Confianza de fabricante separada de confianza de tipo; una MAC aleatoria reduce la confianza del OUI. Apple no implica iPhone y Cisco IOS no implica iOS.
- IDs estables entre tablas y selección: todas las IPs, todas las no móviles, o IDs personalizados. Ambas opciones automáticas excluyen LOCAL; la selección personalizada permite incluirlo. Los equipos desconocidos siguen incluidos en la opción no móvil.
- Escaneo TCP de **1 a 65535**, detección de versiones y scripts NSE `default or vuln`, extracción de referencias CVE, CSV/JSON/XML y logs originales. Algunos scripts de estas categorías pueden ser intrusivos; se solicita autorización de la red antes de comenzar.
- Indicadores de actividad con tiempo transcurrido. Si Nmap emite progreso y ETA, se muestra el porcentaje de **su fase actual**, no un porcentaje global inventado.

El alcance LAN es la subred IPv4 de la ruta predeterminada, con límite de 4096 direcciones. Una huella de SO es una estimación y una referencia CVE no confirma una vulnerabilidad. Los escaneos completos, especialmente Ghost, pueden tardar bastante.

## WIRELESS RECON

En Linux, `iw` enumera interfaces, PHY, controlador, modo actual, conexión, modos admitidos y frecuencias. Se prepara automáticamente una radio compatible y se restaura al terminar; NetworkManager sigue funcionando para las demás interfaces. En Windows se utiliza Native Wi-Fi para descubrir redes y WlanHelper para preparar/restaurar la radio.

| Interfaz | Descubrimiento | Límites |
| --- | --- | --- |
| Managed | `iw dev IFACE scan passive`; si falla, `nmcli device wifi list` | `nmcli` puede usar caché; no expone WPS ni RSSI en dBm en este listado. |
| Monitor dedicada | Captura pasiva de beacons/probe responses con `tcpdump`, recorriendo frecuencias admitidas | Requiere root, canal inicial y radio sin otras interfaces. Restaura la frecuencia al terminar o cancelar. |
| Windows managed | Native Wi-Fi: `WlanScan` + `WlanGetNetworkBssList` | Puede requerir permiso de ubicación; WPS/seguridad según los IE disponibles. |

La tabla muestra ID, SSID, BSSID, canal, seguridad, WPS, señal y evaluación. Un SSID con varios BSSID conserva una fila por punto de acceso. WPA/WPA2/WPA3, PSK/SAE, modos mixtos, OWE y redes abiertas se presentan cuando existe evidencia del backend. Si el AKM no es reconocible, se conserva la incertidumbre. El porcentaje de NetworkManager se muestra como porcentaje, nunca se transforma en dBm.

**WPS es independiente de WPA2/WPA3.** Solo se marca `Detected` si aparece en elementos WPS observados; `Unknown` no equivale a ausencia de WPS. SSID ocultos pueden listarse, pero el detector requiere un SSID exacto y observado. Las bandas disponibles dependen del adaptador, controlador y dominio regulatorio.

### Hardware y VirtualBox

Una interfaz Ethernet virtual, incluso puenteada sobre el Wi-Fi del host, no permite capturar tramas 802.11. En VirtualBox se necesita **passthrough de un adaptador Wi-Fi USB** al invitado, con controlador Linux que admita monitor e inyección. Que `iw` anuncie monitor no garantiza recepción o inyección funcionales. Comprueba `iw dev`, `iw phy`, `rfkill list` y los mensajes de firmware/controlador.

En Kali se guarda el modo original, frecuencia, estado UP/DOWN, gestión de NetworkManager y UUID de la conexión. Se libera **solo esa interfaz** de NetworkManager y se configura con `iw ... set monitor otherbss control`, necesario para recibir otras BSS con controladores como MediaTek. Se fija y verifica la frecuencia antes del detector. Al terminar o cancelar, se restauran modo/estado y la conexión anterior; los fallos se guardan en `radio_setup.json`. No se cambia el dominio regulatorio. [Configuración upstream](https://github.com/qkaiser/broadcom-wps#broadcom-sdk-fingerprinter).

Si falla la restauración se detiene el resto de pruebas. Un apagado o cierre forzado puede impedirla; para recuperar manualmente una interfaz que originalmente estaba en managed, sustituye `wlan1`:

```bash
sudo ip link set dev wlan1 down
sudo iw dev wlan1 set type managed
sudo ip link set dev wlan1 up
sudo nmcli device set wlan1 managed yes
```

En Linux, la aplicación rechaza cambios de canal/pruebas cuando otra interfaz comparte el mismo PHY, aunque parezca desconectada. No cambia automáticamente el dominio regulatorio ni intenta usar canales deshabilitados. Para fingerprint activo también rechaza canales no IR/DFS y 6 GHz, que el adaptador de este detector no maneja sin ambigüedad. En Windows prepara el adaptador compatible y verifica monitor/canal antes de abrir la captura. El descubrimiento puede listar 6 GHz si el hardware lo expone.

### Evaluación WPSplinter

Se integra [`qkaiser/broadcom-wps`](https://github.com/qkaiser/broadcom-wps/tree/3cb3ef77d6b71e8441a51668c7e2b919608180f9), de **Quentin Kaiser**, commit completo **`3cb3ef77d6b71e8441a51668c7e2b919608180f9`**, licencia MIT. Referencia: [One Parser, Two Bugs](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/).

1. Toma el SSID conectado, o el indicado mediante `--ssid`, como alcance autorizado. `--bssid` lo restringe a una radio.
2. Descubre los AP y evalúa secuencialmente solo los BSSID que coinciden con ese alcance.
3. Prepara/restaura automáticamente el adaptador correspondiente al sistema operativo.
4. Cada prueba vuelve a observar pasivamente su SSID/BSSID en su canal antes del intercambio activo.
5. Muestra una sola tabla final con los resultados por BSSID; el resto de redes queda en `NOT_TESTED`.

Se importa la API del detector original, cuya integridad SHA-256 se verifica. Su lanzador por SSID no se utiliza: podría elegir otro BSSID con el mismo nombre. Las decisiones de `fingerprint_target` y `decide_assessment` permanecen sin modificar.

El backend de transporte añade dos restricciones: fija el BSSID seleccionado y bloquea transmisiones de desautenticación/desasociación. El upstream usa desautenticación para cerrar su propia sesión de prueba; aquí se bloquea y se informa honestamente como `cleanup_sent=false`. Una respuesta explícita puede conservar su clasificación mientras `target_health` queda `DEGRADED` según upstream. Puede quedar estado temporal en el AP hasta su timeout; no se afirma que la limpieza haya funcionado. La herramienta no extrae credenciales, ejecuta cargas arbitrarias ni abre shells.

| Salida upstream | Clasificación POLTERHEIST |
| --- | --- |
| `LIKELY_VULNERABLE` | `LIKELY_VULNERABLE` |
| `PATCHED_HOSTAPD` | `PATCHED_HOSTAPD` |
| `NO_BROADCOM_FINGERPRINT` | `NO_BROADCOM_FINGERPRINT` |
| `INCONCLUSIVE` o salida desconocida | `INCONCLUSIVE` |
| Sin autorización / prueba no iniciada | `NOT_TESTED` |
| Error de entorno, de ejecución o discrepancia de objetivo | `ERROR` |

La ausencia de WPS se conserva como `INCONCLUSIVE` según el código del detector. Un resultado positivo identifica comportamiento de una implementación; **no confirma RCE**. Un negativo se limita a este detector y no certifica que el equipo sea seguro.

## Informes

```text
reports/
  lan/<fecha_UTC_microsegundos_id>/
    report.json, report.csv, discovery.json, identification.json, selection.json
    discovery_*.log, discovery_nmap.xml, identify_*.xml, identify_*.log
    scan_*.xml, scan_*.log, scan_*_status.json, results.json
  wireless/<fecha_UTC_microsegundos_id>/
    report.json, discovery.json, iw_scan.log o nmcli_scan.log
    windows_bss.bin, windows_discovery.json  # descubrimiento nativo Windows
    fingerprint.json                   # resumen compatible si hay un único objetivo
    discovery_*MHz.pcap y .log          # si se captura en monitor
    targets/<BSSID_sin_dos_puntos>/
      report.json, fingerprint.json
      radio_setup.json                 # preparación/restauración Linux o Windows
      upstream_result.json, fingerprint.pcap  # si se generan durante la prueba
```

Los informes incluyen versión, hora UTC, objetivo, autorización, fuentes, clasificación, límites y recomendaciones. El informe inalámbrico incluye seguridad, canal, señal, indicadores WPS, identidad de fabricante disponible, salida upstream y hashes de las evidencias. JSON y PCAP originales no se reescriben para cambiar conclusiones. Cada ejecución usa una carpeta nueva. Ctrl+C conserva lo disponible y devuelve al menú; no se inventan resultados para procesos interrumpidos. Un XML truncado se conserva aunque no se pueda analizar.

`reports/`, PCAP, perfil real y entornos virtuales están excluidos de Git para que una subida no publique inventarios de red ni datos personales.

## Pruebas

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Las pruebas sin hardware cubren menú y perfil, descubrimiento LAN combinado, selección/local/Apple, identificación, servicios/CVE, modos, interfaces, WPA/WPA2/WPA3, escapes de SSID, selección/autorización, decisiones **del código upstream real con respuestas simuladas**, bloqueo de desautenticación/otro BSSID, JSON/PCAP y cancelación. Las capturas y salidas de red de los tests son fixtures sintéticos, no mediciones de redes reales.

Si Nmap está instalado, una prueba adicional arranca un servidor HTTP temporal en **127.0.0.1** y lo inspecciona con Nmap real. GitHub Actions ejecuta la suite en **Linux y Windows**, con Python 3.11 y 3.13, e instala Nmap para el test local en Linux. Esta prueba no equivale a validar el escaneo de 65535 puertos, ARP, huellas de SO ni NSE de vulnerabilidades sobre equipos reales.

Otro trabajo de CI usa la imagen oficial `kalilinux/kali-rolling`, ejecuta `script.py --setup` y `--check`, verifica que se detecta Kali y corre la suite dentro de esa distribución. La preparación Linux se prueba con radios simuladas, incluyendo fallos parciales, cancelación, reconexión y exclusión de canales no permitidos. También se verifica que la tabla aparece una sola vez, después de evaluar los BSSID del SSID conectado, sin probar redes de otro nombre.

Los tests de Windows cubren estructuras/offsets de Native Wi-Fi, BSSID múltiples, WPS real en IE sintéticos, WPA/RSN, errores de ubicación/servicio, notificaciones, caché, memoria nativa, conservación de evidencias y adaptación a Npcap. También comprueban elevación UAC simulada, preparación, fallos parciales, cancelación, restauración y reconexión al perfil anterior, además de rechazar controladores sin monitor antes de modificar la radio. El descubrimiento y la lectura del perfil activo se han comprobado con un MediaTek MT7921 en Windows. La preparación y el intercambio WPS activo están validados con mocks; requieren una prueba física con hardware/controlador compatible.

Pendiente de validación física: recepción/inyección monitor, regulación y restauración de canal en cada controlador Linux, y fingerprint de un AP autorizado en ambas plataformas. Los tests automatizados no necesitan ni transmiten tráfico Wi-Fi.

Documentación de referencia: [iw](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html), [nmcli](https://networkmanager.dev/docs/api/latest/nmcli.html) y [salida de Nmap](https://nmap.org/book/man-output.html).
