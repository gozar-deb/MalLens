"""
Celery tasks: the actual analysis pipeline.

Flow for one uploaded sample:
    run_full_analysis (chain)
      -> run_static_analysis     (always runs; pure static parsing)
      -> run_dynamic_analysis    (stub by default; real sandbox if configured)
      -> extract_and_enrich_iocs
      -> generate_report         (score, summary, persist Report row)
"""
from __future__ import annotations

import asyncio
import logging

from app.celery_app import celery_app
from app.config import get_settings
from app.models import Analysis, AnalysisStatus, DynamicResult, IOC, Report, StaticResult, ThreatLevel
from app.services import dynamic_sandbox, ioc_extractor, report_generator, risk_scoring, static_analysis
from app.services import threat_intel
from app.sync_database import SyncSessionLocal

logger = logging.getLogger("mallens.tasks")
settings = get_settings()


@celery_app.task(name="mallens.run_full_analysis", bind=True)
def run_full_analysis(self, analysis_id: str):
    """Entry point enqueued by the /api/upload endpoint."""
    with SyncSessionLocal() as db:
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            logger.error("Analysis %s not found", analysis_id)
            return

        try:
            with open(analysis.storage_path, "rb") as f:
                data = f.read()

            # ---- Static analysis ----
            analysis.status = AnalysisStatus.STATIC_RUNNING
            db.commit()

            static = static_analysis.analyze(data, analysis.file_name, "/app/yara_rules")
            static_row = StaticResult(analysis_id=analysis.id, **static)
            db.add(static_row)
            db.commit()

            # ---- Dynamic analysis ----
            analysis.status = AnalysisStatus.DYNAMIC_RUNNING
            db.commit()

            sandbox = dynamic_sandbox.get_sandbox(
                settings.DYNAMIC_SANDBOX_PROVIDER, settings.CUCKOO_API_URL, settings.CUCKOO_API_TOKEN
            )
            dynamic = sandbox.run(data, analysis.file_name, settings.DYNAMIC_ANALYSIS_TIMEOUT_SECONDS)
            dynamic_row = DynamicResult(analysis_id=analysis.id, **dynamic)
            db.add(dynamic_row)
            db.commit()

            # ---- IOC extraction + enrichment ----
            analysis.status = AnalysisStatus.REPORTING
            db.commit()

            raw_iocs = ioc_extractor.extract_iocs(
                static.get("strings"),
                dynamic.get("network_log"),
                dynamic.get("file_changes"),
                dynamic.get("registry_changes"),
            )
            enriched = asyncio.run(_enrich_all(raw_iocs))
            for ioc in enriched:
                db.add(IOC(analysis_id=analysis.id, **ioc))
            db.commit()

            # ---- Scoring + report ----
            score, level, reasons = risk_scoring.score_analysis(static, dynamic, enriched)
            analysis.threat_score = score
            analysis.threat_level = ThreatLevel(level)

            summary = None
            if settings.OPENAI_API_KEY:
                summary = asyncio.run(
                    report_generator.build_ai_summary(
                        analysis.file_name, level, score, {
                            "file_type": static["file_type"],
                            "entropy": static["entropy"],
                            "yara_matches": len(static.get("yara_matches") or []),
                        },
                        len(enriched), settings.OPENAI_API_KEY, settings.OPENAI_MODEL,
                    )
                )
            generator = "ai" if summary else "template"
            if not summary:
                summary = report_generator.build_template_summary(
                    analysis.file_name, level, score, reasons, len(enriched)
                )

            report_row = Report(
                analysis_id=analysis.id,
                executive_summary=summary,
                detailed_analysis="\n".join(reasons),
                recommendations=report_generator.build_recommendations(level),
                risk_assessment=f"Score {score}/100 ({level}).",
                mitre_mapping=[],
                generator=generator,
            )
            db.add(report_row)

            analysis.status = AnalysisStatus.COMPLETED
            from datetime import datetime
            analysis.completed_at = datetime.utcnow()
            db.commit()

        except Exception as exc:  # noqa: BLE001
            logger.exception("Analysis %s failed", analysis_id)
            analysis.status = AnalysisStatus.ERROR
            analysis.error_message = str(exc)
            db.commit()


async def _enrich_all(raw_iocs: list[dict]) -> list[dict]:
    return [await threat_intel.enrich_ioc(ioc, settings) for ioc in raw_iocs]
