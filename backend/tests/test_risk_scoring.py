from app.services.risk_scoring import score_analysis


def test_benign_when_nothing_found():
    score, level, reasons = score_analysis(
        {"entropy": 3.0, "yara_matches": [], "suspicious_indicators": []}, None, []
    )
    assert level == "benign"
    assert score == 0


def test_high_entropy_and_yara_pushes_to_malicious():
    static = {
        "entropy": 7.9,
        "yara_matches": [{"rule": "Suspicious_PE_Packer_Indicators"}, {"rule": "Possible_Credential_Harvesting_Strings"}],
        "suspicious_indicators": ["VirtualAlloc", "CreateRemoteThread"],
    }
    score, level, reasons = score_analysis(static, {"network_log": [{"host": "1.2.3.4"}]}, [])
    assert level in ("suspicious", "malicious")
    assert score > 30
    assert len(reasons) > 0
