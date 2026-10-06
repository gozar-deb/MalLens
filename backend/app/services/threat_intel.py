"""
Threat-intelligence enrichment clients: VirusTotal, AbuseIPDB, AlienVault OTX.

Every function degrades gracefully (returns None) when its API key isn't
configured, so the rest of the pipeline never depends on any of these being
present. Per the README's privacy policy, only hashes/IOC values are ever
sent to these services -- raw sample bytes are never uploaded to a
third party from here.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx


async def lookup_virustotal(file_hash: str, api_key: Optional[str]) -> Optional[dict[str, Any]]:
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return {"error": f"VT returned {resp.status_code}"}
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": attrs.get("reputation"),
            }
        except httpx.HTTPError as exc:
            return {"error": str(exc)}


async def lookup_abuseipdb(ip: str, api_key: Optional[str]) -> Optional[dict[str, Any]]:
    if not api_key:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code != 200:
                return {"error": f"AbuseIPDB returned {resp.status_code}"}
            d = resp.json().get("data", {})
            return {
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "country_code": d.get("countryCode"),
                "total_reports": d.get("totalReports"),
            }
        except httpx.HTTPError as exc:
            return {"error": str(exc)}


async def lookup_otx(indicator: str, ioc_type: str, api_key: Optional[str]) -> Optional[dict[str, Any]]:
    if not api_key:
        return None
    section_map = {"domain": "domain", "ip": "IPv4", "hash_sha256": "file", "hash_md5": "file"}
    section = section_map.get(ioc_type)
    if not section:
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general"
    headers = {"X-OTX-API-KEY": api_key}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return {"error": f"OTX returned {resp.status_code}"}
            j = resp.json()
            return {"pulse_count": j.get("pulse_info", {}).get("count", 0)}
        except httpx.HTTPError as exc:
            return {"error": str(exc)}


async def enrich_ioc(ioc: dict[str, Any], settings) -> dict[str, Any]:
    """Attach ti_source/ti_data to a single IOC dict in place, if a relevant
    key is configured. Returns the same dict for convenience."""
    ioc_type, value = ioc["ioc_type"], ioc["value"]

    if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256") and settings.VIRUSTOTAL_API_KEY:
        data = await lookup_virustotal(value, settings.VIRUSTOTAL_API_KEY)
        if data and "error" not in data:
            ioc["ti_source"] = "virustotal"
            ioc["ti_data"] = data
            if data.get("malicious", 0) > 0:
                ioc["severity"] = "high"
                ioc["confidence"] = min(1.0, 0.5 + data["malicious"] / 20)

    elif ioc_type == "ip" and settings.ABUSEIPDB_API_KEY:
        data = await lookup_abuseipdb(value, settings.ABUSEIPDB_API_KEY)
        if data and "error" not in data:
            ioc["ti_source"] = "abuseipdb"
            ioc["ti_data"] = data
            score = data.get("abuse_confidence_score") or 0
            if score >= 50:
                ioc["severity"] = "high"
                ioc["confidence"] = score / 100

    elif ioc_type in ("domain", "ip") and settings.OTX_API_KEY:
        data = await lookup_otx(value, ioc_type, settings.OTX_API_KEY)
        if data and "error" not in data:
            ioc["ti_source"] = "otx"
            ioc["ti_data"] = data
            if data.get("pulse_count", 0) > 0:
                ioc["severity"] = "medium"

    return ioc
