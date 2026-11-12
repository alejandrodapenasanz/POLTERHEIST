# H4 — investigación e integración elegida

Consulta: **12-11-2026**. Revisión local: commit base `92ad47c`, Windows 11, Python 3.13. Se conservan `Discovery`, `Endpoint`, `Manager`, `MediaLibrary` y los backends Cast/DLNA. El proceso actual no tiene radio Linux ni herramientas P2P/Miracast. No se han instalado paquetes ni ejecutado proyectos descargados: las consultas a repositorios se usan para leer código y documentación.

## Descubrimiento activo

| Alternativa | Contrato comprobado | Decisión |
| --- | --- | --- |
| NetworkManager WiFiP2P D-Bus | `StartFind(a{sv})`, `StopFind()`, `Peers`; opción `timeout` de tipo entero. API disponible desde NM 1.16. | Backend predeterminado. Usa `busctl` tipado, servicio ya existente, sin activar demonios ni pedir elevación. [API](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Device.WifiP2P.html). |
| wpa_supplicant P2P D-Bus | `Find(a{sv})`, `StopFind()`, `Peers`, `Group`, `Role`; la clave temporal es `Timeout`, con mayúscula. `Peer.IEs` contiene subelementos WFD. | Alternativa seleccionada expresamente por el usuario. No se reintenta automáticamente tras una denegación de permisos de NM. [API del autor](https://w1.fi/wpa_supplicant/devel/dbus.html). |
| `wpa_cli` / socket de control | `P2P_FIND`/`P2P_STOP_FIND`, eventos de peers y detalles del peer. Depende del socket/permisos de la interfaz de control. | Investigado; no se añade una tercera ruta de comandos ni se modifica la configuración del socket. Se prioriza el contrato D-Bus tipado. [Arquitectura P2P](https://w1.fi/wpa_supplicant/devel/p2p.html). |

Find alterna búsqueda/escucha y transmite: **no es escucha pasiva**. El motor consulta interfaces existentes, comprueba el PHY y combinaciones de modos, obtiene evidencia previa, inicia una búsqueda finita y envía StopFind al finalizar/cancelar. No crea una interfaz ni un grupo. Las lecturas `GetAll` no extraen credenciales de perfiles de conexión. El runner usa argumentos, salida acotada y `shell=False`.

Las APIs públicas de descubrimiento no exponen un propietario/lease consultable de cada Find. Por eso se exige confirmar uso exclusivo con otras apps de P2P cerradas y se mantiene un bloqueo por PHY entre procesos POLTERHEIST del workspace. Una respuesta StartFind no demuestra que el driver haya completado una búsqueda física. El código NM consultado puede tramitar el inicio con el supplicant de forma asíncrona. [Implementación NM](https://github.com/NetworkManager/NetworkManager/blob/main/src/core/devices/wifi/nm-device-wifi-p2p.c).

## Evidencia WFD e identidad

El parser interpreta una secuencia de subelementos WFD: ID de un byte, longitud de dos bytes en big-endian y payload. El subelemento Device Information tiene seis bytes: bitmask de dispositivo, puerto de control RTSP y throughput anunciado. Se separan Source, Primary Sink, Secondary Sink y Dual Role; la disponibilidad de sesión no equivale a pairing aceptado. Truncamientos, duplicados o datos sin Device Information nunca se convierten en un receptor por su nombre. La implementación es propia y se limita al formato anunciado, sin copiar una pila Miracast. [Formato usado por FluxCast](https://github.com/IlyaP358/fluxcast/blob/a16ae057f7e155c7102a45045ba41b58a5df55f6/src/wfd/ie.py).

NM publica `Name`, `HwAddress`, `WfdIEs`, fabricante/modelo cuando existen y `LastSeen` en segundos CLOCK_BOOTTIME. Se compara con el comienzo de la búsqueda y con la caché previa; una entrada inalterada del mismo segundo no se promociona a observación nueva. En supplicant, que no publica ese timestamp, las entradas previas sin cambios se mantienen como caché. [Propiedades del peer NM](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.WifiP2PPeer.html).

La identidad de esta entrega es la **dirección P2P exacta más interfaz local de observación**. No se fusiona con una IP o con otro peer por nombre, fabricante, MAC parecida o señal. La misma dirección vista desde dos adaptadores conserva dos observaciones; no se afirma identidad física más allá de esa evidencia. No se inventa una IP antes de formar un enlace.

## Comparación de stacks Miracast

| Candidato | Estado y alcance observados | Integración / dependencias | Efectos y decisión |
| --- | --- | --- | --- |
| GNOME Network Displays | Mirror en `da8f4de9e87c64c37cb2d70720d876c2b4045f98`; mismo HEAD observado el día anterior. Aplicación Linux, P2P/NM y WFD. | GStreamer, H.264, portal/PipeWire y componentes NM/supplicant; RTSP/RTP gestionados por el proyecto. La revisión actual contiene una API `org.gnome.NetworkDisplays.Manager` con Displays/StartStream/StopStream; debe verificarse su presencia en la versión instalada en Kali. | Candidato preferido para evaluación en escritorio GNOME/portal. El inicio de P2P consulta/prepara firewalld; no se verificó una opción que desactive esos efectos. No se arranca automáticamente. [Repositorio](https://github.com/GNOME/gnome-network-displays), [contrato D-Bus](https://github.com/GNOME/gnome-network-displays/blob/da8f4de9e87c64c37cb2d70720d876c2b4045f98/src/org.gnome.NetworkDisplays.Manager.xml), [inicio del sink](https://github.com/GNOME/gnome-network-displays/blob/da8f4de9e87c64c37cb2d70720d876c2b4045f98/src/nd-wfd-p2p-sink.c). |
| FluxCast | HEAD `a16ae057f7e155c7102a45045ba41b58a5df55f6`, release v0.3.0 consultada en H1; su README limita el estado release-ready a WFD. | CLI Python: selección de peer/interfaz, backend NM o supplicant, captura portal/wlroots/X11, FFmpeg/GStreamer/H.264, RTSP/RTP propios. `--wfd-no-firewall` existe en el parser consultado. | Alternativa a evaluar especialmente en wlroots. Ese flag no elimina los cambios de nombre P2P, GO intent ni desconexiones inicial/final del dispositivo P2P. No se ejecuta sin revisar/autorizarlos. [README](https://github.com/IlyaP358/fluxcast), [CLI](https://github.com/IlyaP358/fluxcast/blob/a16ae057f7e155c7102a45045ba41b58a5df55f6/src/main.py), [sesión](https://github.com/IlyaP358/fluxcast/blob/a16ae057f7e155c7102a45045ba41b58a5df55f6/src/wfd/session.py), [parámetros P2P](https://github.com/IlyaP358/fluxcast/blob/a16ae057f7e155c7102a45045ba41b58a5df55f6/src/wfd/p2p/device.py). |
| Pila propia completa | Exigiría negociar P2P, autorización, codecs, RTSP/RTP, captura y limpieza. | Gran superficie sin hardware disponible para validar interoperabilidad. | No elegida. El código nuevo se limita a discovery, evidencia, preparación y presentación local. |

La API Manager encontrada actualiza la hipótesis inicial de H1: hay un contrato D-Bus en el código actual de GNOME, pero eso **no acredita que lo exporte la versión empaquetada de Kali ni su estabilidad entre versiones**. Tampoco su estado `streaming` demostraría por sí solo que la imagen es visible en el televisor. El estado de mantenimiento es una consulta de repositorios, no un benchmark de receptores.

## Frontera de implementación

`MiracastAdapter.prepare` genera un plan revisable con receptor, interfaz, datos WFD, contenido y dependencias detectadas, además de los efectos pendientes de aprobación. `connect` informa que la activación no está implementada en esta entrega; no sustituye una sesión real por una simulación.

`LocalPresentation` abre únicamente contenido validado de `media/` en un proceso ffplay propio, en pantalla completa y bucle, tras confirmación separada. Puede alimentar una futura duplicación de pantalla autorizada; hoy se muestra siempre `LOCAL_PRESENTATION_ONLY`. No lanza capturas, conectores Miracast ni herramientas externas de casting. [Opciones oficiales ffplay](https://ffmpeg.org/ffplay.html).

El siguiente paso técnico es validar Find/StopFind y WFD en Kali físico. Después, revisar versión instalada y efectos exactos del candidato elegido, obtener autorización y conectar el contrato de sesión/captura a un receptor real. Pairing rechazado debe finalizar la sesión; no habrá fallback para evitar PIN o permisos. H4.3/H4.4 no se consideran funcionales hasta cumplir las pruebas físicas definidas por la tarea.
