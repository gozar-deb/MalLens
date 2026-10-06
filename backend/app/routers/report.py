"""GET /api/report/{analysis_id}, DELETE /api/analysis/{analysis_id}"""
import os

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import Analysis, IOC
from app.security import get_current_user
from app.models import User
from app.schemas import DynamicResultOut, FullReportResponse, IOCOut, ReportOut, StaticResultOut
from app.services import report_generator

router = APIRouter(prefix="/api", tags=["report"])


def _ensure_owner(analysis: Analysis, user: User | None) -> None:
    if user is not None and analysis.user_id != user.id:
        raise HTTPException(status_code=404, detail="Analysis not found")


@router.get("/report/{analysis_id}", response_model=FullReportResponse)
async def get_report(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    analysis = await db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    _ensure_owner(analysis, user)

    iocs_result = await db.execute(select(IOC).where(IOC.analysis_id == analysis_id))
    iocs = iocs_result.scalars().all()

    return FullReportResponse(
        analysis_id=analysis.id,
        file_name=analysis.file_name,
        status=analysis.status.value,
        threat_level=analysis.threat_level.value,
        threat_score=analysis.threat_score,
        created_at=analysis.created_at,
        completed_at=analysis.completed_at,
        static=StaticResultOut.model_validate(analysis.static_result) if analysis.static_result else None,
        dynamic=DynamicResultOut.model_validate(analysis.dynamic_result) if analysis.dynamic_result else None,
        iocs=[IOCOut.model_validate(i) for i in iocs],
        report=ReportOut.model_validate(analysis.report) if analysis.report else None,
    )


@router.get("/report/{analysis_id}/export")
async def export_report(
    analysis_id: str,
    format: str = "html",
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    """format = html | pdf | json"""
    analysis = await db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    _ensure_owner(analysis, user)
    if analysis.report is None:
        raise HTTPException(status_code=409, detail="Report not generated yet")

    iocs_result = await db.execute(select(IOC).where(IOC.analysis_id == analysis_id))
    iocs = [IOCOut.model_validate(i).model_dump() for i in iocs_result.scalars().all()]

    context = {
        "file_name": analysis.file_name,
        "sha256": analysis.static_result.hash_sha256 if analysis.static_result else "",
        "threat_level": analysis.threat_level.value,
        "threat_score": analysis.threat_score,
        "executive_summary": analysis.report.executive_summary,
        "recommendations": analysis.report.recommendations,
        "static": StaticResultOut.model_validate(analysis.static_result) if analysis.static_result else None,
        "iocs": iocs,
        "generated_at": analysis.report.generated_at,
    }

    if format == "json":
        full = FullReportResponse(
            analysis_id=analysis.id,
            file_name=analysis.file_name,
            status=analysis.status.value,
            threat_level=analysis.threat_level.value,
            threat_score=analysis.threat_score,
            created_at=analysis.created_at,
            completed_at=analysis.completed_at,
            static=StaticResultOut.model_validate(analysis.static_result) if analysis.static_result else None,
            dynamic=DynamicResultOut.model_validate(analysis.dynamic_result) if analysis.dynamic_result else None,
            iocs=[IOCOut.model_validate(i) for i in iocs_result.scalars().all()],
            report=ReportOut.model_validate(analysis.report),
        )
        return Response(content=full.model_dump_json(indent=2), media_type="application/json")

    if format == "pdf":
        pdf_bytes = report_generator.render_pdf(context)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="mallens_{analysis_id[:8]}.pdf"'},
        )

    html = report_generator.render_html(context)
    return Response(content=html, media_type="text/html")


@router.delete("/analysis/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    analysis = await db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    _ensure_owner(analysis, user)

    if os.path.exists(analysis.storage_path):
        os.remove(analysis.storage_path)

    await db.delete(analysis)
    await db.commit()
    return {"deleted": True, "analysis_id": analysis_id}
