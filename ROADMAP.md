# POLTERHEIST TV engine — roadmap

Updated **2026-11-12**. Implemented code, automated validation and physical interoperability are separate milestones.

| Milestone | Current delivery | Remaining validation/work |
| --- | --- | --- |
| H1 — Research | Protocol/vendor matrices and architecture. [H4 research update](docs/tv_engine/H4_RESEARCH.md). | Recheck versions and effects before adopting an external Miracast stack. |
| H2 — Hardware | Read-only Kali diagnosis, including Wi-Fi PHYs, P2P, BlueZ and media prerequisites. | Execute on physical Kali hardware; advertised capability is not a working session. |
| H3 — IP discovery | Cast, UPnP/DLNA/DIAL, AirPlay/RAOP and explicit routed IPv4 scopes. | Physical receivers, routed media return path and IPv6 transport. |
| H4.1 — P2P discovery | NetworkManager and explicitly selected supplicant D-Bus backends, physical-interface/PHY selection, bounded Find/StopFind, cancellation, state comparison and reports. | Exercise real radios/drivers, permissions, coexistence and cleanup on Kali. |
| H4.2 — Classification | Strict WFD subelement parsing, sink/source/P2P-only distinctions, freshness/cache evidence and scoped inventory. | Compare advertisements with receiver model/firmware and actual acceptance. |
| H4.3 — Miracast connection | External-stack research and preparation adapter; dependency/effects/blocker report. | **Not functional/validated:** review installed stack and approve required changes, then implement/validate pairing, connection, RTSP/RTP and teardown on hardware. No full Miracast stack rewritten. |
| H4.4 — Miracast media | Image/video selection and a separately confirmed local looping presentation process, suitable for a future screen-mirroring session. | **Not functional/validated on a receiver:** wire an authorized Miracast session to capture/presentation and verify picture/sound/stop physically. |
| H4.5–H4.8 | Multiple PHYs, interference guards, explicit errors, CLI integration and automated tests. | Driver-specific coexistence and physical failure testing. See [H4 validation](docs/tv_engine/H4_VALIDATION.md). |
| H5 — Vendors | Research only. | Official pairing and supported vendor/control-platform APIs. |
| H6 — Media expansion | Existing Cast/DLNA image/video sessions retained. | New audio, RTSP/RTP, capture and transport implementations. |
| H7 — Intelligence | Conservative inventory and protocol identities. | Verified correlation, secure capability cache and path selection. |
| H8 — Hardware acceptance | Automated regressions and labeled simulators. | Physical Kali/receiver matrix; no compatibility claims based on fixtures. |

Next step: run H4.1/H4.2 on physical Kali with an authorized WFD receiver in its screen-mirroring discovery mode. Use the evidence to choose and approve an installed Miracast stack before activation. This delivery does not install packages, start external casting tools, change firewall/routes or disconnect existing networks.
