"""
SQLite database layer for storing scan runs and findings.
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
import os
from pathlib import Path
from typing import Optional

from app.models import Asset, Evidence, Finding, RunStatus, ScanRun, Severity

# Use local data folder if /data doesn't exist (non-Docker mode)
DATA_DIR = Path(os.environ.get("DATA_DIR", "./data"))
if not DATA_DIR.exists():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "scanner.db"


def init_db():
    """Initialize the database with required tables."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Create runs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER DEFAULT 0,
                max_duration_sec INTEGER DEFAULT 300,
                lab_mode INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                error_message TEXT
            )
        """)
        
        # Create findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                asset_value TEXT NOT NULL,
                category TEXT NOT NULL,
                check_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_details TEXT NOT NULL,
                evidence_headers TEXT,
                evidence_artifact_path TEXT,
                remediation TEXT NOT NULL,
                source TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(id)
            )
        """)
        
        conn.commit()

        # Lightweight migration for older DBs missing lab_mode
        cursor.execute("PRAGMA table_info(runs)")
        columns = {row[1] for row in cursor.fetchall()}
        if "lab_mode" not in columns:
            cursor.execute("ALTER TABLE runs ADD COLUMN lab_mode INTEGER DEFAULT 0")
            conn.commit()


@contextmanager
def get_connection():
    """Get a database connection with context manager."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ============ RUN OPERATIONS ============

def create_run(run: ScanRun) -> ScanRun:
    """Insert a new scan run into the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO runs (id, target_url, status, progress, max_duration_sec, lab_mode, created_at, updated_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.id,
                run.target_url,
                run.status.value,
                run.progress,
                run.max_duration_sec,
                1 if run.lab_mode else 0,
                run.created_at.isoformat(),
                run.updated_at.isoformat(),
                run.error_message,
            ),
        )
        conn.commit()
    return run


def get_run(run_id: str) -> Optional[ScanRun]:
    """Retrieve a scan run by ID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        return ScanRun(
            id=row["id"],
            target_url=row["target_url"],
            status=RunStatus(row["status"]),
            progress=row["progress"],
            max_duration_sec=row["max_duration_sec"],
            lab_mode=bool(row["lab_mode"]) if "lab_mode" in row.keys() else False,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            error_message=row["error_message"],
        )


def update_run_status(run_id: str, status: RunStatus, progress: int, error_message: Optional[str] = None):
    """Update the status and progress of a scan run."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE runs SET status = ?, progress = ?, updated_at = ?, error_message = ?
            WHERE id = ?
            """,
            (status.value, progress, datetime.utcnow().isoformat(), error_message, run_id),
        )
        conn.commit()


def update_run_progress(run_id: str, progress: int):
    """Update just the progress of a scan run."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE runs SET progress = ?, updated_at = ?
            WHERE id = ?
            """,
            (progress, datetime.utcnow().isoformat(), run_id),
        )
        conn.commit()


# ============ FINDING OPERATIONS ============

def save_finding(finding: Finding):
    """Save a finding to the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings 
            (id, run_id, asset_type, asset_value, category, check_name, severity, summary, 
             evidence_details, evidence_headers, evidence_artifact_path, remediation, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.id,
                finding.run_id,
                finding.asset.type,
                finding.asset.value,
                finding.category,
                finding.check,
                finding.severity.value,
                finding.summary,
                finding.evidence.details,
                json.dumps(finding.evidence.headers),
                finding.evidence.artifact_path,
                json.dumps(finding.remediation),
                finding.source,
            ),
        )
        conn.commit()


def save_findings(findings: list[Finding]):
    """Save multiple findings to the database."""
    for finding in findings:
        save_finding(finding)


def get_findings_for_run(run_id: str) -> list[Finding]:
    """Retrieve all findings for a specific run."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,))
        rows = cursor.fetchall()
        
        findings = []
        for row in rows:
            finding = Finding(
                id=row["id"],
                asset=Asset(type=row["asset_type"], value=row["asset_value"]),
                category=row["category"],
                check=row["check_name"],
                severity=Severity(row["severity"]),
                summary=row["summary"],
                evidence=Evidence(
                    details=row["evidence_details"],
                    headers=json.loads(row["evidence_headers"]) if row["evidence_headers"] else {},
                    artifact_path=row["evidence_artifact_path"],
                ),
                remediation=json.loads(row["remediation"]),
                source=row["source"],
                run_id=row["run_id"],
            )
            findings.append(finding)
        
        return findings


def count_findings_by_severity(run_id: str) -> dict[str, int]:
    """Count findings by severity for a run."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT severity, COUNT(*) as count 
            FROM findings 
            WHERE run_id = ? 
            GROUP BY severity
            """,
            (run_id,),
        )
        rows = cursor.fetchall()
        return {row["severity"]: row["count"] for row in rows}
