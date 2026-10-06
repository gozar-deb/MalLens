"""GET /api/dashboard"""
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Analysis, AnalysisStatus, IOC, ThreatLevel
from app.schemas import DashboardStats

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard", response_model=DashboardStats)
async def dashboard(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Analysis))
    analyses = result.scalars().all()

    total = len(analyses)
    completed = sum(1 for a in analyses if a.status == AnalysisStatus.COMPLETED)
    pending = sum(
        1 for a in analyses
        if a.status in (AnalysisStatus.PENDING, AnalysisStatus.STATIC_RUNNING, AnalysisStatus.DYNAMIC_RUNNING, AnalysisStatus.REPORTING)
    )
    high_risk = sum(1 for a in analyses if a.threat_level == ThreatLevel.MALICIOUS)

    breakdown = Counter(a.threat_level.value for a in analyses)

    ioc_result = await db.execute(select(IOC.value, IOC.ioc_type))
    ioc_rows = ioc_result.all()
    top = Counter((v, t) for v, t in ioc_rows)
    top_iocs = [{"value": v, "type": t, "count": c} for (v, t), c in top.most_common(10)]

    since = datetime.utcnow() - timedelta(days=13)
    buckets: dict[str, int] = {}
    for a in analyses:
        if a.created_at >= since:
            key = a.created_at.date().isoformat()
            buckets[key] = buckets.get(key, 0) + 1
    over_time = [{"date": k, "count": v} for k, v in sorted(buckets.items())]

    return DashboardStats(
        total_analyses=total,
        completed=completed,
        pending_or_running=pending,
        high_risk_count=high_risk,
        threat_level_breakdown=dict(breakdown),
        top_iocs=top_iocs,
        analyses_over_time=over_time,
    )
