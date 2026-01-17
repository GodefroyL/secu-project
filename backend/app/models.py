"""
Data models for the security scanner application.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4


class RunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class Asset:
    type: str  # "url", "domain", "ip"
    value: str


@dataclass
class Evidence:
    details: str
    headers: dict = field(default_factory=dict)
    artifact_path: Optional[str] = None


@dataclass
class Finding:
    id: str
    asset: Asset
    category: str  # e.g., "OWASP A05"
    check: str  # e.g., "zap_baseline", "tls_probe", "headers_probe"
    severity: Severity
    summary: str
    evidence: Evidence
    remediation: list[str]
    source: str  # "zap" or "custom_probe"
    run_id: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "asset": {"type": self.asset.type, "value": self.asset.value},
            "category": self.category,
            "check": self.check,
            "severity": self.severity.value,
            "summary": self.summary,
            "evidence": {
                "details": self.evidence.details,
                "headers": self.evidence.headers,
                "artifact_path": self.evidence.artifact_path,
            },
            "remediation": self.remediation,
            "source": self.source,
            "run_id": self.run_id,
        }


@dataclass
class ScanRun:
    id: str
    target_url: str
    status: RunStatus
    progress: int  # 0-100
    max_duration_sec: int
    lab_mode: bool
    created_at: datetime
    updated_at: datetime
    error_message: Optional[str] = None

    @classmethod
    def create(cls, target_url: str, max_duration_sec: int = 300, lab_mode: bool = False) -> "ScanRun":
        now = datetime.utcnow()
        return cls(
            id=str(uuid4()),
            target_url=target_url,
            status=RunStatus.QUEUED,
            progress=0,
            max_duration_sec=max_duration_sec,
            lab_mode=lab_mode,
            created_at=now,
            updated_at=now,
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "status": self.status.value,
            "progress": self.progress,
            "max_duration_sec": self.max_duration_sec,
            "lab_mode": self.lab_mode,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "error_message": self.error_message,
        }
