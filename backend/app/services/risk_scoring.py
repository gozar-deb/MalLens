"""
Heuristic risk scoring.

Combines static-analysis signals (entropy, YARA hits, suspicious API
usage), dynamic-analysis signals, and IOC severities into a single
0-100 threat_score and a coarse ThreatLevel. This is a transparent,
explainable heuristic, not a machine-learning classifier -- every
contribution to the score is listed in `reasons` so it's auditable.
"""
from __future__ import annotations

from typing import Any


def score_analysis(
    static_result: dict[str, Any] | None,
    dynamic_result: dict[str, Any] | None,
    iocs: list[dict[str, Any]],
) -> tuple[float, str, list[str]]:
    score = 0.0
    reasons: list[str] = []

    if static_result:
        entropy = static_result.get("entropy", 0)
        if entropy >= 7.5:
            score += 20
            reasons.append(f"High file entropy ({entropy}) suggests packing/encryption.")
        elif entropy >= 6.5:
            score += 8
            reasons.append(f"Elevated file entropy ({entropy}).")

        yara_matches = static_result.get("yara_matches") or []
        if yara_matches:
            score += min(30, 10 * len(yara_matches))
            reasons.append(
                f"{len(yara_matches)} YARA rule(s) matched: "
                + ", ".join(m["rule"] for m in yara_matches[:5])
            )

        suspicious = static_result.get("suspicious_indicators") or []
        if suspicious:
            score += min(20, 3 * len(suspicious))
            reasons.append(f"{len(suspicious)} suspicious API reference(s) found.")

    if dynamic_result:
        net = dynamic_result.get("network_log")
        if net:
            score += 10
            reasons.append("Dynamic analysis observed outbound network activity.")
        reg = dynamic_result.get("registry_changes")
        if reg:
            score += 5
            reasons.append("Dynamic analysis observed registry modification.")

    high_sev_iocs = [i for i in iocs if i.get("severity") == "high"]
    if high_sev_iocs:
        score += min(20, 5 * len(high_sev_iocs))
        reasons.append(f"{len(high_sev_iocs)} IOC(s) flagged high-severity by threat intel.")

    score = round(min(100.0, score), 1)

    if score >= 70:
        level = "malicious"
    elif score >= 30:
        level = "suspicious"
    elif score > 0:
        level = "suspicious" if reasons else "benign"
    else:
        level = "benign"

    if not reasons:
        reasons.append("No suspicious static or dynamic indicators were found.")

    return score, level, reasons
