# Third-party code

`vendor/broadcom-wps/broadcom_fingerprint.py`, `README.md`, and `LICENSE.md` are unchanged copies from https://github.com/qkaiser/broadcom-wps at commit `3cb3ef77d6b71e8441a51668c7e2b919608180f9`.

Copyright (c) 2026 Quentin Kaiser. MIT license; complete text in [`vendor/broadcom-wps/LICENSE.md`](vendor/broadcom-wps/LICENSE.md). [`UPSTREAM.json`](vendor/broadcom-wps/UPSTREAM.json) records provenance and SHA-256 hashes. `.gitattributes` prevents line-ending conversion for these files.

POLTERHEIST imports the implementation and adds BSSID scope/authorization, inventory, reports, and transport restrictions in `script.py`. Windows temporarily adapts capture/transmit and channel checks to Scapy/Npcap/WlanHelper. The upstream file and detection decisions remain unchanged. Blocking upstream deauthentication cleanup is explicitly documented in reports and the README.
