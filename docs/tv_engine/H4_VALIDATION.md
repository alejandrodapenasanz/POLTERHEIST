# H4 — entrega, límites y validación

Fecha: **12-11-2026**. Entorno de desarrollo ejecutado: **Windows 11 / Python 3.13**. H4.1/H4.2 tienen código real para Linux y pruebas automatizadas; todavía no tienen validación física. H4.3/H4.4 son preparación y presentación local: **no establecen ni certifican una sesión Miracast**.

## Archivos y funcionalidades

| Archivos | Cambio |
| --- | --- |
| `tv_control/wireless_bus.py` | Runner de argumentos acotado, respuesta JSON tipada de busctl, errores categorizados; sin shell, sudo, activación de servicios ni autorización interactiva. |
| `tv_control/p2p.py` | Inventario de interfaces/PHY, driver/chipset, coexistencia y backends D-Bus NM/supplicant. Solo Find/StopFind modifican el estado temporal de búsqueda. |
| `tv_control/wfd.py` | Valida dirección P2P y subelementos WFD; distingue fuente, receptores, peer genérico, datos malformados y disponibilidad anunciada. |
| `tv_control/wireless.py` | Ciclo de estados, cancelación, timeout finito, bloqueo por PHY, comparación antes/después y reportes JSON. |
| `tv_control/discovery.py` | Observaciones de radio sin IP inventada; actualización por interfaz, IDs estables y preservación de resultados IP al actualizar radio y viceversa. |
| `tv_control/miracast.py`, `wireless_cli.py` | Preparación de candidato/contenido, dependencias y efectos pendientes; proceso ffplay local propio con bucle/cancelación/limpieza. Sin activar Miracast. |
| `tv_control/cli.py`, `manager.py` | Menú inalámbrico disponible aunque falte una LAN IPv4; motor Cast/DLNA conservado y reproducción IP bloqueada cuando no hay interfaz seleccionada. |
| `tv_control/models.py`, `config/tv_control.example.json` | `p2p_backend` y `p2p_timeout`, con límites validados. |
| `tv_control/hardware.py` | Lecturas D-Bus mediante `call Properties.Get`, para aplicar efectivamente la prohibición de autoactivar servicios. |
| `tests/test_wireless_tv.py`, `tests/test_tv_engine.py` | Fixtures H4 identificados como SIMULATED y regresión de las lecturas de diagnóstico sin autoactivación. |
| `ROADMAP.md`, README y documentación TV/H4 | Alcance implementado, investigación de stacks y siguiente validación. |

No hay nuevas dependencias Python. No se instalaron paquetes ni cambiaron configuración de red, servicios, radios, firewall o rutas del host. El código no ejecuta `Set`, `CreateInterface`, `Connect`, `Disconnect`, `Flush`, WPS ni comandos de monitor mode durante discovery. La [investigación H4](H4_RESEARCH.md) explica por qué no se lanza automáticamente un stack Miracast externo.

## Menú y configuración

Se conservan las opciones TV Control 0–7. Se añaden:

```text
[8] Wi-Fi Direct discovery
[9] Miracast receivers (WFD advertisements)
[10] Prepare Miracast / local presentation
```

La opción 8 enumera interfaces con su PHY, driver y capacidades. Una selección manual identifica la interfaz exacta; no se interpreta que dos interfaces sean dos radios independientes. Se comprueban las combinaciones de modos de `iw phy` y el estado actual. Con una conexión managed activa y coexistencia desconocida/incompatible, se rechaza la operación y se recomienda otro adaptador libre; no se desconecta la red. AP, monitor o grupos P2P existentes en el PHY también bloquean la búsqueda.

Antes de Find se pide confirmar el ámbito radio y cerrar otras apps de P2P. La búsqueda predeterminada dura **15 segundos**, configurable entre 1 y 60. La duración no incluye inventario/comprobaciones previas ni limpieza. Las consultas D-Bus duran hasta 3 segundos más 0,2 de margen para terminar el cliente; las salidas se limitan a 256 KiB. El inventario de cada servicio tiene presupuesto de 15 segundos y las consultas de enlaces, 10. Las consultas ya iniciadas pueden retrasar brevemente Ctrl+C; siempre se intenta la limpieza.

```json
{
  "p2p_backend": "networkmanager",
  "p2p_timeout": 15
}
```

Añadir estas claves al archivo local `config/tv_control.json` si ya existe; no reemplazar otros ajustes. El ejemplo completo está en `config/tv_control.example.json`. La opción 7 permite seleccionar `networkmanager` o `supplicant` para esa sesión. **Seleccionar un backend no inicia una búsqueda** y no hay fallback automático ante permisos denegados.

## Estados y garantías prácticas

`CHECKING → STARTING → DISCOVERING → STOPPING` termina en `COMPLETED`, `NO_PEERS`, `CACHE_ONLY`, `CANCELLED`, `ERROR` o `CLEANUP_UNVERIFIED`. Los errores incluyen `P2P_UNSUPPORTED`, `ADAPTER_BUSY`, `DRIVER_UNSUPPORTED`, `PERMISSION_DENIED`, `NETWORKMANAGER_UNAVAILABLE`, `SUPPLICANT_UNAVAILABLE`, `TIMEOUT` y `PLATFORM_UNSUPPORTED`.

Un inicio rechazado por busy/permisos/API no envía StopFind sobre una operación ajena. Si el inicio expira sin respuesta, su ejecución es incierta y se intenta StopFind. El timeout finito solicitado al demonio limita la búsqueda aunque el cliente desaparezca. El bloqueo por PHY se libera al cerrar el proceso; coordina instancias de este workspace, no aplicaciones externas. NM/supplicant no proporcionan una propiedad pública que acredite quién posee una búsqueda ajena; cerrar otras apps sigue siendo necesario.

`stop_confirmed` significa que la API respondió a StopFind, **no una medición radio**. `state_preserved` compara el estado observable de interfaces, asociación/canal, conexiones y datos P2P; no implica una auditoría completa del driver. El backend no altera configuración que deba reescribir. Si el estado cambia o no se puede verificar, informa `CLEANUP_UNVERIFIED`; no aplica un reconnect/reset que pudiera interrumpir actividad externa. Después de ese resultado, esperar al timeout del demonio y revisar el informe antes de otra operación.

Las entradas NM se consideran recientes solo con timestamp coherente y nuevo/cambiado respecto a la caché previa. Supplicant no expone LastSeen en esta API: los registros sin cambios se conservan como caché. `NO_PEERS` no prueba que no exista una TV cercana: el receptor debe anunciarse, el driver puede tener límites, o el protocolo puede requerir otros anuncios. Esta entrega no cambia los WFD IEs locales/globales para forzar que un receptor responda.

Una TV por nombre sigue siendo `P2P ONLY` si no aporta WFD válido. Una fuente WFD no es un receptor. `WFD CAPABLE` es una capacidad anunciada, no PIN aceptado ni vídeo verificado. Las entradas de caché no son destinos disponibles. La misma dirección P2P observada por dos adaptadores conserva ambas observaciones, sin correlacionarla con Cast/DLNA por nombre o MAC similar.

Informes locales: `reports/tv_control/wireless_<UTC>.json`, `discovery_<UTC>.json`, `miracast_plan_<UTC>.json` y `tv_control.log`. Están ignorados por Git; pueden contener direcciones y nombres del laboratorio. Los fixtures de tests nunca se cargan en producción.

## Preparación Miracast y medios

La opción 10 produce un plan con receptor/interfaz, WFD, contenido opcional, herramientas disponibles y efectos pendientes de revisión. El adaptador `connect` rechaza la activación en esta entrega. No hay negociación P2P, PIN, RTSP/RTP ni captura implementados por este adaptador. Por tanto, los errores reales de pairing rechazado, conexión Miracast, negociación RTSP y streaming remoto permanecen pendientes de la integración física; no se simulan como validación.

Se puede seleccionar una imagen/vídeo de `media/` y confirmar **LOCAL presentation only**. Se valida con el motor multimedia existente y se abre ffplay en pantalla completa/bucle. ENTER o Ctrl+C lo termina y libera el proceso propio; cerrar su ventana también acaba la reproducción. Se acota la salida de diagnóstico del reproductor. Este mecanismo está preparado para aportar contenido a una futura sesión de duplicación autorizada: hoy **no envía contenido a la TV**. Los fallos de reproductor/dependencia se reportan como locales.

## Dependencias pendientes

| Función | Herramientas/requisitos que debe tener Kali |
| --- | --- |
| Discovery P2P | Python y dependencias previas; `iw`, `busctl` con JSON; NetworkManager con WiFiP2P o wpa_supplicant D-Bus/P2P ya disponible; driver/firmware/PHY compatibles y permisos de consulta/búsqueda. |
| Diagnóstico | Herramientas enumeradas por H2; las ausentes se registran sin instalar. |
| Presentación local | FFmpeg/ffprobe y **ffplay**, entorno gráfico funcional. ffplay no está incluido en la copia local Windows de FFmpeg de este workspace. |
| Miracast futuro | GNOME Network Displays o alternativa revisada, wpa_supplicant con WFD, codecs H.264 y componentes GStreamer, portal/PipeWire/captura adecuados al escritorio. La lista exacta depende del candidato y versión. |

Primero recoger el diagnóstico; después preparar una instalación/cambio concreto para autorización. Tener un binario o un encoder listado no demuestra que funcione con la GPU o receptor.

## Comandos exactos para Kali Live

Usar la venv Linux existente; si setup creó `.venv-linux`, sustituir el ejecutable en estos comandos. No ejecutar una venv Windows desde Kali.

```bash
.venv/bin/python script.py --tv-diagnostics
.venv/bin/python script.py --tv-control
```

En TV Control: **8 → número del adaptador → `y`**, y después **9** para filtrar receptores WFD o **5** para inspeccionar toda la evidencia. Si no hay LAN, el menú continúa disponible. Cambiar al backend supplicant mediante **7** únicamente si está disponible y se desea probarlo expresamente.

Lecturas opcionales de comprobación, sin activar servicios:

```bash
iw dev
iw phy
nmcli -t -f DEVICE,TYPE,STATE device status
busctl --system --auto-start=no --allow-interactive-authorization=no call \
  fi.w1.wpa_supplicant1 /fi/w1/wpa_supplicant1 \
  org.freedesktop.DBus.Properties Get ss fi.w1.wpa_supplicant1 Capabilities
busctl --system --auto-start=no --allow-interactive-authorization=no call \
  fi.w1.wpa_supplicant1 /fi/w1/wpa_supplicant1 \
  org.freedesktop.DBus.Properties Get ss fi.w1.wpa_supplicant1 WFDIEs
```

Pruebas automatizadas, sin radio ni receptor:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_wireless_tv.py' -v
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m ruff check script.py POLTERHEIST.py tv_control tests
.venv/bin/python -m ruff format --check script.py POLTERHEIST.py tv_control tests
```

Si Ruff u otra herramienta falta, el comando informará del problema; estos comandos no la instalan.

## Registro automatizado

Se ejecutan los comandos anteriores con `.venv\Scripts\python.exe` en Windows. Para las pruebas reales de conversión se añade `.venv\ffmpeg-tools` únicamente al PATH del proceso. El diagnóstico real del backend inalámbrico en Windows devuelve `PLATFORM_UNSUPPORTED` antes de invocar herramientas Linux.

- **57 pruebas H4**: parsers, tipos JSON, cuerpos D-Bus, adaptadores/PHY, coexistencia, inicio/stop, cancelación, timeouts, caché, bloqueo, cambio externo de estado, selección/menú, preparación y limpieza del proceso local.
- Dos recorridos de integración pasan por JSON busctl → backend real → inventario → Find → peers → StopFind → verificación, con servicio/runner **SIMULATED**. No usan un bus ni un driver reales.
- La regresión inicial encontró que una actualización vacía de una interfaz podía volver a marcar un peer antiguo como disponible. Corregido usando únicamente identidades recientes del resultado actual.
- Una ejecución de la suite anterior produjo un bloqueo de DLL de `zeroconf` por Windows Application Control. La importación posterior funcionó sin alterar políticas ni reinstalar; la suite se volvió a ejecutar. Este incidente queda registrado como limitación del entorno.
- Resultado final de suite/lint: ver la anotación de cierre al final de este documento.

## Prueba física necesaria

En un receptor propio, activar su modo de descubrimiento/duplicación Miracast. Registrar Kali/kernel, chipset/driver, PHY/interfaz, conexiones existentes, modelo/firmware TV y backend elegido. Verificar una búsqueda normal, otra cancelada con Ctrl+C y otra sin receptor visible. Comparar estado previo/posterior y comprobar que la conexión managed sigue operativa. Con dos adaptadores, repetir cada ámbito y confirmar que actualizar uno conserva el otro.

Solo después elegir/versionar el stack, revisar/aprobar sus cambios y realizar pairing/captura/reproducción real. Registrar aceptación o rechazo, estado P2P, RTSP, encoder, imagen en la TV y teardown. **H4.3 y H4.4 seguirán pendientes hasta que esas comprobaciones se completen.**

## Cierre de validación — 12-11-2026

Resultado final en Windows 11 / Python 3.13.15:

- `python -m unittest discover -s tests`: **284 pruebas, 283 correctas y 1 omitida**, en 50,049 segundos. La omisión corresponde a Nmap no disponible. Incluye las 57 pruebas H4 y las regresiones anteriores; FFmpeg/ffprobe estaban disponibles en el PATH del proceso.
- `python -m ruff check script.py POLTERHEIST.py tv_control tests`: **All checks passed**.
- `python -m ruff format --check script.py POLTERHEIST.py tv_control tests`: **34 archivos con formato correcto**.
- `git diff --check`: correcto.
- `python -m pip check`: **No broken requirements found**.
- Ejecución real de `WirelessDiscovery.adapters()` en este host: **PLATFORM_UNSUPPORTED (win32)**, sin invocar herramientas Linux. Evidencia local en `reports/tv_control/h4_windows_guard.json`.

No se probó una radio Linux, pairing, reproducción local gráfica ni recepción Miracast física. Los recorridos P2P automatizados usan los fixtures identificados como SIMULATED.
