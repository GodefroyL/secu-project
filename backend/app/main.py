"""
FastAPI Backend for Security Scanner MVP.
"""
import logging
import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, field_validator

from app.db import (
    create_run,
    get_findings_for_run,
    get_run,
    init_db,
)
from app.models import RunStatus, ScanRun
from app.runner import get_report_path, start_scan_in_background

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Security Scanner API",
    description="API for automated web security scanning (MVP)",
    version="1.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============ Request/Response Models ============

class ScanRequest(BaseModel):
    """Request to start a new security scan."""
    target_url: str
    max_duration_sec: int = 300

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate and normalize the target URL."""
        v = v.strip()
        
        # Add scheme if missing
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"
        
        # Parse and validate URL
        try:
            parsed = urlparse(v)
            if not parsed.netloc:
                raise ValueError("Invalid URL: no domain specified")
            
            # Basic domain validation
            domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
            hostname = parsed.hostname or ""
            
            # Allow IP addresses
            ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
            
            if not (re.match(domain_pattern, hostname) or re.match(ip_pattern, hostname)):
                raise ValueError(f"Invalid domain: {hostname}")
            
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")
        
        return v

    @field_validator("max_duration_sec")
    @classmethod
    def validate_duration(cls, v: int) -> int:
        """Validate scan duration."""
        if v < 60:
            raise ValueError("Minimum duration is 60 seconds")
        if v > 1800:
            raise ValueError("Maximum duration is 1800 seconds (30 minutes)")
        return v


class ScanResponse(BaseModel):
    """Response after creating a new scan."""
    run_id: str


class StatusResponse(BaseModel):
    """Response with scan status."""
    status: str
    progress: int
    target_url: Optional[str] = None
    error_message: Optional[str] = None


# ============ Startup ============

@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    logger.info("Initializing database...")
    init_db()
    
    # Ensure data directories exist
    data_dir = Path(os.environ.get("DATA_DIR", "./data"))
    (data_dir / "runs").mkdir(parents=True, exist_ok=True)
    logger.info("Security Scanner API ready")


# ============ Health Check ============

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "security-scanner-api"}


# ============ Scan Endpoints ============

@app.post("/runs", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    """
    Create and start a new security scan.
    
    This initiates a non-destructive passive security scan of the target URL.
    """
    logger.info(f"Creating scan for {request.target_url}")
    
    # Create run in database
    run = ScanRun.create(
        target_url=request.target_url,
        max_duration_sec=request.max_duration_sec,
    )
    create_run(run)
    
    # Start scan in background
    start_scan_in_background(run)
    
    logger.info(f"Scan {run.id} created and started")
    return ScanResponse(run_id=run.id)


@app.get("/runs/{run_id}", response_model=StatusResponse)
async def get_scan_status(run_id: str):
    """
    Get the status of a security scan.
    """
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return StatusResponse(
        status=run.status.value,
        progress=run.progress,
        target_url=run.target_url,
        error_message=run.error_message,
    )


@app.get("/runs/{run_id}/findings")
async def get_scan_findings(run_id: str):
    """
    Get the findings (vulnerabilities) from a security scan.
    """
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = get_findings_for_run(run_id)
    return {
        "run_id": run_id,
        "status": run.status.value,
        "target_url": run.target_url,
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


@app.get("/runs/{run_id}/report")
async def get_scan_report(run_id: str):
    """
    Download the HTML report for a completed scan.
    """
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if run.status != RunStatus.FINISHED:
        raise HTTPException(
            status_code=400, 
            detail=f"Report not available. Scan status: {run.status.value}"
        )
    
    report_path = get_report_path(run_id)
    if not report_path or not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    
    return FileResponse(
        path=str(report_path),
        filename=f"security_report_{run_id}.html",
        media_type="text/html",
    )


# ============ Error Handlers ============

@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    """Handle validation errors."""
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc)},
    )


@app.exception_handler(Exception)
async def generic_error_handler(request, exc):
    """Handle unexpected errors."""
    logger.exception(f"Unexpected error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
