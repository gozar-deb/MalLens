"""Pydantic request/response schemas."""
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field


class UploadResponse(BaseModel):
    analysis_id: str
    file_name: str
    status: str
    message: str = "File accepted and queued for analysis."


class StatusResponse(BaseModel):
    analysis_id: str
    file_name: str
    status: str
    threat_level: str
    threat_score: float
    created_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class StaticResultOut(BaseModel):
    hash_md5: str
    hash_sha1: str
    hash_sha256: str
    file_type: str
    file_size: int
    entropy: float
    imports: Optional[dict[str, Any]] = None
    sections: Optional[dict[str, Any]] = None
    strings: Optional[list[str]] = None
    yara_matches: Optional[list[dict[str, Any]]] = None
    suspicious_indicators: Optional[list[str]] = None

    class Config:
        from_attributes = True


class DynamicResultOut(BaseModel):
    provider: str
    process_logs: Optional[list[dict[str, Any]]] = None
    file_changes: Optional[list[dict[str, Any]]] = None
    registry_changes: Optional[list[dict[str, Any]]] = None
    network_log: Optional[list[dict[str, Any]] | dict[str, Any]] = None
    behavior_timeline: Optional[list[dict[str, Any]]] = None
    runtime_seconds: Optional[float] = None
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class IOCOut(BaseModel):
    ioc_type: str
    value: str
    context: Optional[str] = None
    severity: str
    confidence: float
    ti_source: Optional[str] = None
    ti_data: Optional[dict[str, Any]] = None

    class Config:
        from_attributes = True


class ReportOut(BaseModel):
    executive_summary: Optional[str] = None
    detailed_analysis: Optional[str] = None
    recommendations: Optional[str] = None
    risk_assessment: Optional[str] = None
    mitre_mapping: Optional[list[dict[str, Any]]] = None
    generated_at: datetime
    generator: str

    class Config:
        from_attributes = True


class FullReportResponse(BaseModel):
    analysis_id: str
    file_name: str
    status: str
    threat_level: str
    threat_score: float
    created_at: datetime
    completed_at: Optional[datetime] = None
    static: Optional[StaticResultOut] = None
    dynamic: Optional[DynamicResultOut] = None
    iocs: list[IOCOut] = Field(default_factory=list)
    report: Optional[ReportOut] = None


class QueueItem(BaseModel):
    analysis_id: str
    file_name: str
    status: str
    threat_level: str
    created_at: datetime


class DashboardStats(BaseModel):
    total_analyses: int
    completed: int
    pending_or_running: int
    high_risk_count: int
    threat_level_breakdown: dict[str, int]
    top_iocs: list[dict[str, Any]]
    analyses_over_time: list[dict[str, Any]]


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
