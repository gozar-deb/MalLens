"""
Report generation: executive summary (template or AI), HTML, and PDF export.

The AI summary is entirely optional (OPENAI_API_KEY). Without a key, a
deterministic template-based summary is used instead, so reports are always
generated even in a zero-external-dependency deployment.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from jinja2 import Template

HTML_TEMPLATE = Template("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>MalLens Report - {{ file_name }}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0b0e11; color:#e6e9ee; margin:0; padding:2rem; }
  h1 { color:#f2b134; }
  .badge { display:inline-block; padding:.25rem .75rem; border-radius:999px; font-weight:600; font-size:.85rem; }
  .badge.malicious { background:#3a1414; color:#ff6b6b; }
  .badge.suspicious { background:#3a2f14; color:#f2b134; }
  .badge.benign { background:#123a1e; color:#5fd68a; }
  .section { margin-top:2rem; padding:1.25rem; background:#151a21; border-radius:12px; border:1px solid #262d38; }
  table { width:100%; border-collapse:collapse; margin-top:.5rem; }
  td, th { text-align:left; padding:.4rem .6rem; border-bottom:1px solid #262d38; font-size:.9rem; }
  code { background:#0b0e11; padding:.1rem .35rem; border-radius:4px; }
</style>
</head>
<body>
  <h1>MalLens Analysis Report</h1>
  <p><strong>{{ file_name }}</strong> &middot; <code>{{ sha256 }}</code></p>
  <span class="badge {{ threat_level }}">{{ threat_level|upper }} &middot; score {{ threat_score }}/100</span>

  <div class="section">
    <h2>Executive Summary</h2>
    <p>{{ executive_summary }}</p>
  </div>

  <div class="section">
    <h2>Static Analysis</h2>
    <table>
      <tr><th>File type</th><td>{{ static.file_type if static else "n/a" }}</td></tr>
      <tr><th>Entropy</th><td>{{ static.entropy if static else "n/a" }}</td></tr>
      <tr><th>MD5</th><td><code>{{ static.hash_md5 if static else "" }}</code></td></tr>
      <tr><th>SHA1</th><td><code>{{ static.hash_sha1 if static else "" }}</code></td></tr>
      <tr><th>YARA matches</th><td>{{ (static.yara_matches|length) if static else 0 }}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>IOCs ({{ iocs|length }})</h2>
    <table>
      <tr><th>Type</th><th>Value</th><th>Severity</th><th>Source</th></tr>
      {% for ioc in iocs %}
      <tr><td>{{ ioc.ioc_type }}</td><td><code>{{ ioc.value }}</code></td><td>{{ ioc.severity }}</td><td>{{ ioc.ti_source or "-" }}</td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="section">
    <h2>Recommendations</h2>
    <p>{{ recommendations }}</p>
  </div>

  <p style="opacity:.6; margin-top:2rem; font-size:.8rem;">
    Generated {{ generated_at }} by MalLens. For authorized security research and incident response use only.
  </p>
</body>
</html>
""")


def build_template_summary(
    file_name: str,
    threat_level: str,
    threat_score: float,
    reasons: list[str],
    ioc_count: int,
) -> str:
    lead = {
        "malicious": f"{file_name} exhibits strong indicators of malicious behavior",
        "suspicious": f"{file_name} shows some indicators worth further review",
        "benign": f"{file_name} did not trigger significant static or dynamic indicators",
    }.get(threat_level, f"{file_name} was analyzed")

    body = f"{lead} (risk score {threat_score}/100). "
    if reasons:
        body += " ".join(reasons) + " "
    body += f"{ioc_count} indicator(s) of compromise were extracted from static and dynamic analysis."
    return body


async def build_ai_summary(
    file_name: str,
    threat_level: str,
    threat_score: float,
    static_summary: dict[str, Any],
    ioc_count: int,
    api_key: Optional[str],
    model: str,
) -> Optional[str]:
    """Optional LLM-generated executive summary. Returns None if no API key
    is configured, or on any API error, so callers should fall back to
    build_template_summary()."""
    if not api_key:
        return None

    try:
        from openai import AsyncOpenAI
    except ImportError:
        return None

    prompt = (
        f"Write a 3-4 sentence executive summary for a malware analysis report.\n"
        f"File: {file_name}\n"
        f"Assessed threat level: {threat_level} (score {threat_score}/100)\n"
        f"Static analysis findings: {static_summary}\n"
        f"Number of extracted IOCs: {ioc_count}\n"
        f"Write for a SOC analyst audience. Be factual and concise. Do not speculate beyond the given data."
    )
    try:
        client = AsyncOpenAI(api_key=api_key)
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
        )
        return resp.choices[0].message.content
    except Exception:  # noqa: BLE001 - AI summary is best-effort
        return None


def render_html(context: dict[str, Any]) -> str:
    return HTML_TEMPLATE.render(**context)


def render_pdf(html_context: dict[str, Any]) -> bytes:
    """Render a simple PDF report using reportlab (no external HTML-to-PDF
    engine required, so this works in a minimal container)."""
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("MalLens Analysis Report", styles["Title"]),
        Paragraph(html_context["file_name"], styles["Heading2"]),
        Paragraph(
            f"Threat level: {html_context['threat_level'].upper()} "
            f"(score {html_context['threat_score']}/100)",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("Executive Summary", styles["Heading3"]),
        Paragraph(html_context["executive_summary"], styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Indicators of Compromise", styles["Heading3"]),
    ]

    if html_context["iocs"]:
        data = [["Type", "Value", "Severity"]] + [
            [i["ioc_type"], i["value"][:60], i["severity"]] for i in html_context["iocs"][:50]
        ]
        table = Table(data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#151a21")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]
            )
        )
        story.append(table)
    else:
        story.append(Paragraph("No IOCs were extracted.", styles["Normal"]))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Recommendations", styles["Heading3"]))
    story.append(Paragraph(html_context["recommendations"], styles["Normal"]))

    doc.build(story)
    return buf.getvalue()


def build_recommendations(threat_level: str) -> str:
    return {
        "malicious": (
            "Isolate any host that executed this file immediately. Rotate credentials that "
            "may have been exposed. Block the extracted network IOCs at the perimeter. "
            "Preserve the sample and this report for incident response."
        ),
        "suspicious": (
            "Treat this file as untrusted pending further review. Cross-check the extracted "
            "IOCs against your SIEM/EDR. Consider a full manual reverse-engineering pass "
            "before allowing execution in any environment."
        ),
        "benign": (
            "No significant indicators were found. As with any user-submitted file, standard "
            "email/attachment hygiene still applies -- this result does not guarantee the file "
            "is safe against a targeted or novel threat."
        ),
    }.get(threat_level, "Review the findings above and apply your organization's incident-response playbook.")
