"""GET /api/queue"""
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Analysis
from app.schemas import QueueItem
from app.security import get_current_user

router = APIRouter(prefix="/api", tags=["queue"])


@router.get("/queue", response_model=list[QueueItem])
async def list_queue(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    stmt = select(Analysis).order_by(Analysis.created_at.desc()).limit(limit)
    if user is not None:
        stmt = stmt.where(Analysis.user_id == user.id)
    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [
        QueueItem(
            analysis_id=a.id,
            file_name=a.file_name,
            status=a.status.value,
            threat_level=a.threat_level.value,
            created_at=a.created_at,
        )
        for a in rows
    ]
