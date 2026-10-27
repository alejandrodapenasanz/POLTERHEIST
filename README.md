# POLTERHEIST

Herramienta de inventario y evaluación de redes propias o autorizadas para **Kali Linux**, con interfaz de terminal verde, el nuevo arte ASCII y tres entradas:

```text
[0] WHO AM I?
[1] LAN RECON
[2] WIRELESS RECON

[q] EXIT
```

La aplicación está en **`script.py`**, organizada por funciones. Se ha evolucionado el código LAN existente; `POLTERHEIST.py` sigue funcionando como entrada compatible. El detector externo permanece separado en `vendor/` para conservar su código original, licencia y procedencia.

## Instalación en Kali

Python **3.11 o posterior**:

```bash
sudo apt update
sudo apt install python3 python3-venv nmap arp-scan iproute2 iw network-manager tcpdump
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python script.py --check
sudo .venv/bin/python script.py
```

`requirements.txt` fija Scapy 2.7.0. Los comandos del sistema se instalan con `apt`, no con `pip`. Menú, perfil y parsers no requieren root. LAN, captura monitor y fingerprint WPS sí. `arp-scan` es recomendable; si falta o falla, el descubrimiento continúa con Nmap. Para una captura con `tcpdump` se necesita el soporte libpcap que instala el paquete de Kali.

En Windows funcionan el menú, el perfil y las pruebas sin hardware. Los flujos de reconocimiento requieren Linux; instalar solamente Nmap para Windows no proporciona `iw`, `ip` o `arp-scan`.

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

`iw` enumera interfaces, PHY, controlador, modo actual, conexión, modos admitidos y frecuencias. El programa no detiene NetworkManager ni convierte automáticamente una interfaz a monitor.

| Interfaz | Descubrimiento | Límites |
| --- | --- | --- |
| Managed | `iw dev IFACE scan passive`; si falla, `nmcli device wifi list` | `nmcli` puede usar caché; no expone WPS ni RSSI en dBm en este listado. |
| Monitor dedicada | Captura pasiva de beacons/probe responses con `tcpdump`, recorriendo frecuencias admitidas | Requiere root, canal inicial y radio sin otras interfaces. Restaura la frecuencia al terminar o cancelar. |

La tabla muestra ID, SSID, BSSID, canal, seguridad, WPS, señal y evaluación. Un SSID con varios BSSID conserva una fila por punto de acceso. WPA/WPA2/WPA3, PSK/SAE, modos mixtos, OWE y redes abiertas se presentan cuando existe evidencia del backend. Si el AKM no es reconocible, se conserva la incertidumbre. El porcentaje de NetworkManager se muestra como porcentaje, nunca se transforma en dBm.

**WPS es independiente de WPA2/WPA3.** Solo se marca `Detected` si aparece en elementos WPS observados; `Unknown` no equivale a ausencia de WPS. SSID ocultos pueden listarse, pero el detector requiere un SSID exacto y observado. Las bandas disponibles dependen del adaptador, controlador y dominio regulatorio.

### Hardware y VirtualBox

Una interfaz Ethernet virtual, incluso puenteada sobre el Wi-Fi del host, no permite capturar tramas 802.11. En VirtualBox se necesita **passthrough de un adaptador Wi-Fi USB** al invitado, con controlador Linux que admita monitor e inyección. Que `iw` anuncie monitor no garantiza recepción o inyección funcionales. Comprueba `iw dev`, `iw phy`, `rfkill list` y los mensajes de firmware/controlador.

Para evaluar WPS usa un adaptador dedicado, sin una conexión que necesites conservar. Estos comandos son **manuales** y desconectarán la interfaz indicada; sustituye `wlan1` solo por ese adaptador:

```bash
sudo nmcli device set wlan1 managed no
sudo ip link set dev wlan1 down
sudo iw dev wlan1 set monitor otherbss control
sudo ip link set dev wlan1 up
sudo iw dev wlan1 set channel 6
sudo tcpdump -i wlan1 -e -n -c 5 'type mgt subtype beacon'
```

Al acabar, si quieres devolver ese adaptador a managed:

```bash
sudo ip link set dev wlan1 down
sudo iw dev wlan1 set type managed
sudo ip link set dev wlan1 up
sudo nmcli device set wlan1 managed yes
```

La aplicación rechaza cambios de canal/pruebas cuando otra interfaz comparte el mismo PHY, aunque parezca desconectada. No cambia automáticamente el dominio regulatorio ni intenta usar canales deshabilitados. Para fingerprint activo también rechaza canales no IR/DFS y 6 GHz, que el adaptador de este detector no maneja sin ambigüedad. El descubrimiento puede listar 6 GHz si el hardware lo expone.

### Evaluación WPSplinter

Se integra [`qkaiser/broadcom-wps`](https://github.com/qkaiser/broadcom-wps/tree/3cb3ef77d6b71e8441a51668c7e2b919608180f9), de **Quentin Kaiser**, commit completo **`3cb3ef77d6b71e8441a51668c7e2b919608180f9`**, licencia MIT. Referencia: [One Parser, Two Bugs](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/).

1. Descubre redes y selecciona un ID concreto.
2. Selecciona una interfaz monitor dedicada.
3. Confirma el SSID/BSSID mostrado escribiendo **`AUTORIZO aa:bb:cc:dd:ee:ff`**, con el BSSID elegido.
4. Se vuelve a observar pasivamente ese SSID/BSSID en su canal antes del intercambio activo. No se evalúan automáticamente otros AP.

Se importa la API del detector original, cuya integridad SHA-256 se verifica. Su lanzador por SSID no se utiliza: podría elegir otro BSSID con el mismo nombre. Las decisiones de `fingerprint_target` y `decide_assessment` permanecen sin modificar.

El backend de transporte añade dos restricciones: fija el BSSID seleccionado y bloquea transmisiones de desautenticación/desasociación. El upstream usa desautenticación para cerrar su propia sesión de prueba; aquí se bloquea y se informa honestamente como `cleanup_sent=false`. Una respuesta explícita puede conservar su clasificación mientras `target_health` queda `DEGRADED` según upstream. Puede quedar estado temporal en el AP hasta su timeout; no se afirma que la limpieza haya funcionado. La herramienta no extrae credenciales, ejecuta cargas arbitrarias ni abre shells.

| Salida upstream | Clasificación POLTERHEIST |
| --- | --- |
| `LIKELY_VULNERABLE` | `LIKELY_VULNERABLE` |
| `PATCHED_HOSTAPD` | `NOT_VULNERABLE_PER_DETECTOR` |
| `NO_BROADCOM_FINGERPRINT` | `NOT_VULNERABLE_PER_DETECTOR` |
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
    discovery_*MHz.pcap y .log          # si se captura en monitor
    upstream_result.json, fingerprint.pcap  # si se generan durante la prueba
```

Los informes incluyen versión, hora UTC, objetivo, autorización, fuentes, clasificación, límites y recomendaciones. El informe inalámbrico incluye seguridad, canal, señal, indicadores WPS, identidad de fabricante disponible, salida upstream y hashes de las evidencias. JSON y PCAP originales no se reescriben para cambiar conclusiones. Cada ejecución usa una carpeta nueva. Ctrl+C conserva lo disponible y devuelve al menú; no se inventan resultados para procesos interrumpidos. Un XML truncado se conserva aunque no se pueda analizar.

`reports/`, PCAP, perfil real y entornos virtuales están excluidos de Git para que una subida no publique inventarios de red ni datos personales.

## Pruebas

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Las pruebas sin hardware cubren menú y perfil, descubrimiento LAN combinado, selección/local/Apple, identificación, servicios/CVE, modos, interfaces, WPA/WPA2/WPA3, escapes de SSID, selección/autorización, decisiones **del código upstream real con respuestas simuladas**, bloqueo de desautenticación/otro BSSID, JSON/PCAP y cancelación. Las capturas y salidas de red de los tests son fixtures sintéticos, no mediciones de redes reales.

Si Nmap está instalado, una prueba adicional arranca un servidor HTTP temporal en **127.0.0.1** y lo inspecciona con Nmap real. GitHub Actions instala Nmap en Linux y ejecuta la suite con Python 3.11 y 3.13. Esta prueba no equivale a validar el escaneo de 65535 puertos, ARP, huellas de SO ni NSE de vulnerabilidades sobre equipos reales.

Pendiente de validación física: recepción/inyección 802.11, regulación y restauración de canal en cada controlador, descubrimiento RF y fingerprint de un AP autorizado. Los tests no necesitan ni transmiten tráfico Wi-Fi.

Documentación de referencia: [iw](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html), [nmcli](https://networkmanager.dev/docs/api/latest/nmcli.html) y [salida de Nmap](https://nmap.org/book/man-output.html).
