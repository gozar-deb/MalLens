"""GET /api/status/{analysis_id}"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Analysis, User
from app.security import get_current_user
from app.schemas import StatusResponse

router = APIRouter(prefix="/api", tags=["status"])


@router.get("/status/{analysis_id}", response_model=StatusResponse)
async def get_status(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    analysis = await db.get(Analysis, analysis_id)
    if analysis is None or (user is not None and analysis.user_id != user.id):
        raise HTTPException(status_code=404, detail="Analysis not found")

    return StatusResponse(
        analysis_id=analysis.id,
        file_name=analysis.file_name,
        status=analysis.status.value,
        threat_level=analysis.threat_level.value,
        threat_score=analysis.threat_score,
        created_at=analysis.created_at,
        completed_at=analysis.completed_at,
        error_message=analysis.error_message,
    )
