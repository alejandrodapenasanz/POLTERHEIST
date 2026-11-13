"""Explain observed exposure without inventing CVEs or control permissions."""

import datetime


def assess(device):
    findings = []
    for endpoint in device.endpoints:
        if endpoint.details.get("web_url", "").startswith("http://"):
            findings.append(
                {
                    "kind": "EXPOSURE",
                    "severity": "INFORMATIONAL",
                    "protocol": endpoint.protocol,
                    "title": "Plain HTTP service advertised",
                    "evidence": endpoint.details["web_url"],
                    "meaning": "An advertisement does not prove that credentials or sensitive data are transmitted in cleartext.",
                    "next_step": "Check the documented login method and HTTPS support before entering credentials.",
                }
            )
        mqtt = endpoint.details.get("mqtt_check", {})
        if mqtt.get("return_code") == 0:
            findings.append(
                {
                    "kind": "EXPOSURE",
                    "severity": "REVIEW REQUIRED",
                    "protocol": endpoint.protocol,
                    "title": "Anonymous MQTT session accepted",
                    "evidence": {
                        "observed_at": mqtt["observed_at"],
                        "ip": endpoint.ip,
                        "port": endpoint.port,
                    },
                    "meaning": "Broker accepted CONNECT without credentials. Subscription, publishing and device control permissions were not tested.",
                    "next_step": "Confirm whether anonymous connections are intended and review broker ACLs using a dedicated laboratory topic.",
                }
            )
    return {
        "device_id": device.id,
        "available": device.available,
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "OBSERVATIONS ONLY",
        "findings": findings,
        "cve_matching_performed": False,
        "exploit_executed": False,
        "limitations": [
            "No findings does not mean the device is secure.",
            "Advertised metadata is untrusted; firmware/CVE applicability requires corroboration.",
            "Cached observations may no longer describe the current device state.",
        ],
    }
