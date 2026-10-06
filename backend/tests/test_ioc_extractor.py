"""Unit tests for ioc_extractor.py regex extraction and dedup."""
from app.services.ioc_extractor import dedupe_and_score, extract_from_text, extract_iocs


def test_extracts_url():
    iocs = extract_from_text("beacon to http://evil.example.com/gate.php now", "static")
    types = {i["ioc_type"] for i in iocs}
    assert "url" in types


def test_extracts_public_ip_but_not_private():
    iocs = extract_from_text("connects to 8.8.8.8 and 192.168.1.5 and 10.0.0.1", "dynamic")
    values = {i["value"] for i in iocs if i["ioc_type"] == "ip"}
    assert "8.8.8.8" in values
    assert "192.168.1.5" not in values
    assert "10.0.0.1" not in values


def test_extracts_domain():
    iocs = extract_from_text("resolves badstuff.xyz for c2", "static")
    values = {i["value"] for i in iocs if i["ioc_type"] == "domain"}
    assert "badstuff.xyz" in values


def test_extracts_sha256_hash():
    h = "a" * 64
    iocs = extract_from_text(f"drops file {h}", "dynamic")
    values = {i["value"] for i in iocs if i["ioc_type"] == "hash_sha256"}
    assert h in values


def test_dedupe_removes_duplicates():
    raw = [
        {"ioc_type": "ip", "value": "8.8.8.8", "context": "static"},
        {"ioc_type": "ip", "value": "8.8.8.8", "context": "dynamic"},
    ]
    deduped = dedupe_and_score(raw)
    assert len(deduped) == 1


def test_extract_iocs_end_to_end():
    strings = ["contact http://c2.example.net/beacon", "192.0.2.10 not private"]
    iocs = extract_iocs(strings, None, None, None)
    assert any(i["ioc_type"] == "url" for i in iocs)
    assert any(i["ioc_type"] == "ip" for i in iocs)
