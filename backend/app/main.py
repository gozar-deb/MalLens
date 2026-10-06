"""MalLens FastAPI application entry point."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import init_models
from app.routers import auth, dashboard, queue, report, status, upload

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_models()
    yield


app = FastAPI(
    title="MalLens API",
    description=(
        "Defensive malware behavior analyzer. Static + dynamic analysis, "
        "IOC extraction, and report generation. Authorized security "
        "research / incident response use only."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router)
app.include_router(status.router)
app.include_router(report.router)
app.include_router(queue.router)
app.include_router(dashboard.router)
app.include_router(auth.router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "app": settings.APP_NAME}
