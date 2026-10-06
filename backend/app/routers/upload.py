"""POST /api/upload"""
import hashlib
import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import Analysis, AnalysisStatus
from app.schemas import UploadResponse
from app.security import get_current_user
from app.tasks import run_full_analysis
from app.utils.file_validation import validate_upload

router = APIRouter(prefix="/api", tags=["upload"])
settings = get_settings()


@router.post("/upload", response_model=UploadResponse)
async def upload_file(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    contents = await file.read()
    header = contents[:16]

    result = validate_upload(file.filename or "unknown", header, len(contents), settings.MAX_UPLOAD_SIZE_MB)
    if not result.allowed:
        raise HTTPException(status_code=400, detail=result.reason)

    analysis_id = str(uuid.uuid4())
    sha256 = hashlib.sha256(contents).hexdigest()

    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    storage_path = os.path.join(settings.UPLOAD_DIR, f"{analysis_id}_{sha256[:12]}")
    with open(storage_path, "wb") as f:
        f.write(contents)

    analysis = Analysis(
        id=analysis_id,
        user_id=user.id if user else None,
        file_name=file.filename or "unknown",
        file_hash=sha256,
        file_size=len(contents),
        mime_type=file.content_type,
        storage_path=storage_path,
        status=AnalysisStatus.PENDING,
    )
    db.add(analysis)
    await db.commit()

    run_full_analysis.delay(analysis_id)

    return UploadResponse(analysis_id=analysis_id, file_name=analysis.file_name, status=analysis.status.value)
