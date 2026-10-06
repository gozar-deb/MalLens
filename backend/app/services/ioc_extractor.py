"""
IOC extraction.

Parses static-analysis strings and dynamic-analysis logs to harvest
Indicators of Compromise: IPs, domains, URLs, hashes, mutexes, email
addresses, and registry keys. De-duplicates and does light categorization.
Enrichment with external threat-intel is a separate step (threat_intel.py)
so extraction always works even with zero API keys configured.
"""
from __future__ import annotations

import re
from typing import Any

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|io|ru|cn|xyz|top|club|online|site|link|icu|cc|tk)\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MUTEX_HINT_RE = re.compile(r"\b(?:Global\\|Local\\)[\w.\-]{3,64}\b")
REGISTRY_RE = re.compile(
    r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[\w\\ .\-{}]+", re.IGNORECASE
)

# Private / reserved ranges we don't want flagged as "network IOCs".
_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "0.")


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(_PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        return 16 <= second <= 31
    return False


def extract_from_text(text: str, context: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    for m in URL_RE.finditer(text):
        found.append({"ioc_type": "url", "value": m.group(), "context": context})

    for m in IP_RE.finditer(text):
        ip = m.group()
        if not _is_private_ip(ip):
            found.append({"ioc_type": "ip", "value": ip, "context": context})

    for m in DOMAIN_RE.finditer(text):
        found.append({"ioc_type": "domain", "value": m.group().lower(), "context": context})

    for m in EMAIL_RE.finditer(text):
        found.append({"ioc_type": "email", "value": m.group().lower(), "context": context})

    for m in SHA256_RE.finditer(text):
        found.append({"ioc_type": "hash_sha256", "value": m.group().lower(), "context": context})

    for m in SHA1_RE.finditer(text):
        found.append({"ioc_type": "hash_sha1", "value": m.group().lower(), "context": context})

    for m in MD5_RE.finditer(text):
        found.append({"ioc_type": "hash_md5", "value": m.group().lower(), "context": context})

    for m in MUTEX_HINT_RE.finditer(text):
        found.append({"ioc_type": "mutex", "value": m.group(), "context": context})

    for m in REGISTRY_RE.finditer(text):
        found.append({"ioc_type": "registry_key", "value": m.group(), "context": context})

    return found


def dedupe_and_score(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for ioc in iocs:
        key = (ioc["ioc_type"], ioc["value"])
        if key not in seen:
            seen[key] = {**ioc, "severity": "info", "confidence": 0.5}
    return list(seen.values())


def extract_iocs(
    static_strings: list[str] | None,
    dynamic_network_log: list | dict | None,
    dynamic_file_changes: list | None,
    dynamic_registry_changes: list | None,
) -> list[dict[str, Any]]:
    all_iocs: list[dict[str, Any]] = []

    if static_strings:
        all_iocs += extract_from_text("\n".join(static_strings), context="static")

    if dynamic_network_log:
        all_iocs += extract_from_text(str(dynamic_network_log), context="dynamic")

    if dynamic_file_changes:
        all_iocs += extract_from_text(str(dynamic_file_changes), context="dynamic")

    if dynamic_registry_changes:
        all_iocs += extract_from_text(str(dynamic_registry_changes), context="dynamic")

    return dedupe_and_score(all_iocs)
