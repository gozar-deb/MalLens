"""Celery application instance. Run with:
    celery -A app.celery_app worker --loglevel=info
(see the `worker` service in docker-compose.yml)
"""
from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "mallens",
    broker=settings.broker_url,
    backend=settings.result_backend,
    include=["app.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.DYNAMIC_ANALYSIS_TIMEOUT_SECONDS + 60,
)
