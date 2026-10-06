"""SQLAlchemy ORM models matching the schema described in README.md."""
import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    STATIC_RUNNING = "static_running"
    DYNAMIC_RUNNING = "dynamic_running"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ERROR = "error"
    REJECTED = "rejected"  # e.g. disallowed file type, oversized, flagged as illegal content


class ThreatLevel(str, enum.Enum):
    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    analyses: Mapped[list["Analysis"]] = relationship(back_populates="user")


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id"), nullable=True
    )
    file_name: Mapped[str] = mapped_column(String(512))
    file_hash: Mapped[str] = mapped_column(String(64), index=True)  # sha256
    file_size: Mapped[int] = mapped_column(Integer)
    mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    storage_path: Mapped[str] = mapped_column(String(1024))

    status: Mapped[AnalysisStatus] = mapped_column(
        Enum(AnalysisStatus), default=AnalysisStatus.PENDING
    )
    threat_level: Mapped[ThreatLevel] = mapped_column(
        Enum(ThreatLevel), default=ThreatLevel.UNKNOWN
    )
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped["User | None"] = relationship(back_populates="analyses")
    static_result: Mapped["StaticResult | None"] = relationship(
        back_populates="analysis", uselist=False, cascade="all, delete-orphan"
    )
    dynamic_result: Mapped["DynamicResult | None"] = relationship(
        back_populates="analysis", uselist=False, cascade="all, delete-orphan"
    )
    iocs: Mapped[list["IOC"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    report: Mapped["Report | None"] = relationship(
        back_populates="analysis", uselist=False, cascade="all, delete-orphan"
    )


class StaticResult(Base):
    __tablename__ = "static_results"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    analysis_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("analyses.id"))

    hash_md5: Mapped[str] = mapped_column(String(32))
    hash_sha1: Mapped[str] = mapped_column(String(40))
    hash_sha256: Mapped[str] = mapped_column(String(64))
    file_type: Mapped[str] = mapped_column(String(128))
    file_size: Mapped[int] = mapped_column(Integer)
    entropy: Mapped[float] = mapped_column(Float)
    imports: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    sections: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    strings: Mapped[list | None] = mapped_column(JSON, nullable=True)
    yara_matches: Mapped[list | None] = mapped_column(JSON, nullable=True)
    suspicious_indicators: Mapped[list | None] = mapped_column(JSON, nullable=True)

    analysis: Mapped["Analysis"] = relationship(back_populates="static_result")


class DynamicResult(Base):
    __tablename__ = "dynamic_results"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    analysis_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("analyses.id"))

    provider: Mapped[str] = mapped_column(String(32))  # "stub" | "cuckoo"
    process_logs: Mapped[list | None] = mapped_column(JSON, nullable=True)
    file_changes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    registry_changes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    network_log: Mapped[list | None] = mapped_column(JSON, nullable=True)
    behavior_timeline: Mapped[list | None] = mapped_column(JSON, nullable=True)
    runtime_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    analysis: Mapped["Analysis"] = relationship(back_populates="dynamic_result")


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    analysis_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("analyses.id"))

    ioc_type: Mapped[str] = mapped_column(String(32))  # ip, domain, url, hash, mutex, email, registry_key
    value: Mapped[str] = mapped_column(String(1024), index=True)
    context: Mapped[str | None] = mapped_column(String(64), nullable=True)  # "static" | "dynamic"
    severity: Mapped[str] = mapped_column(String(16), default="info")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    ti_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ti_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    analysis: Mapped["Analysis"] = relationship(back_populates="iocs")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    analysis_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("analyses.id"))

    executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    detailed_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_assessment: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_mapping: Mapped[list | None] = mapped_column(JSON, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    generator: Mapped[str] = mapped_column(String(32), default="template")  # "template" | "ai"

    analysis: Mapped["Analysis"] = relationship(back_populates="report")
