"""
Scan Runner - Orchestrates the security scan workflow.
"""
import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from app.db import (
    get_findings_for_run,
    get_run,
    save_findings,
    update_run_progress,
    update_run_status,
)
from app.models import RunStatus, ScanRun
from app.probes import HeadersProbe, TLSProbe
from app.reporting import ReportBuilder
from backend.app.attacks.lab_attacks import run_lab_attacks

# ZAP is optional (requires Docker)
ZAP_ENABLED = os.environ.get("ZAP_ENABLED", "false").lower() == "true"
if ZAP_ENABLED:
    from app.zap import ZAPParser, ZAPRunner

logger = logging.getLogger(__name__)

# Thread pool for running scans
executor = ThreadPoolExecutor(max_workers=4)


async def run_scan(run: ScanRun):
    """
    Execute the complete security scan workflow.
    
    1. Update status to running
    2. Run TLS probe
    3. Run headers probe
    4. Run lab-mode active attacks (if enabled)
    5. Run ZAP baseline scan (if enabled)
    6. Parse and save findings
    7. Generate report
    8. Update status to finished
    """
    run_id = run.id
    target_url = run.target_url
    
    try:
        logger.info(f"Starting scan {run_id} for {target_url}")
        update_run_status(run_id, RunStatus.RUNNING, 5)
        
        all_findings = []
        
        # Phase 1: TLS Probe (5-30%)
        logger.info(f"[{run_id}] Running TLS probe...")
        try:
            tls_probe = TLSProbe(run_id)
            tls_findings = tls_probe.analyze(target_url)
            all_findings.extend(tls_findings)
            logger.info(f"[{run_id}] TLS probe found {len(tls_findings)} issues")
        except Exception as e:
            logger.error(f"[{run_id}] TLS probe error: {e}")
        update_run_progress(run_id, 30)
        
        # Phase 2: Headers Probe (30-60%)
        logger.info(f"[{run_id}] Running headers probe...")
        try:
            headers_probe = HeadersProbe(run_id)
            headers_findings = await headers_probe.analyze(target_url)
            all_findings.extend(headers_findings)
            logger.info(f"[{run_id}] Headers probe found {len(headers_findings)} issues")
        except Exception as e:
            logger.error(f"[{run_id}] Headers probe error: {e}")
        update_run_progress(run_id, 60)
        
        # Phase 3: Lab-mode active attacks (60-70%) - Optional
        if run.lab_mode:
            logger.info(f"[{run_id}] Running lab-mode active tests...")
            try:
                lab_findings = run_lab_attacks(target_url, run_id)
                all_findings.extend(lab_findings)
                logger.info(f"[{run_id}] Lab-mode tests produced {len(lab_findings)} findings")
            except Exception as e:
                logger.error(f"[{run_id}] Lab-mode tests error: {e}")
        else:
            logger.info(f"[{run_id}] Lab-mode tests skipped")
        update_run_progress(run_id, 70)

        # Phase 4: ZAP Baseline Scan (70-85%) - Optional
        if ZAP_ENABLED:
            logger.info(f"[{run_id}] Running ZAP baseline scan...")
            try:
                zap_runner = ZAPRunner(run_id)
                success, result = await zap_runner.run_baseline_scan(
                    target_url, 
                    run.max_duration_sec
                )
                
                if success:
                    # Parse ZAP results
                    zap_parser = ZAPParser(run_id)
                    zap_findings = zap_parser.parse_report(result)
                    all_findings.extend(zap_findings)
                    logger.info(f"[{run_id}] ZAP scan found {len(zap_findings)} issues")
                else:
                    logger.warning(f"[{run_id}] ZAP scan issue: {result}")
            except Exception as e:
                logger.error(f"[{run_id}] ZAP scan error: {e}")
        else:
            logger.info(f"[{run_id}] ZAP scan skipped (Docker not available)")
        update_run_progress(run_id, 85)
        
        # Phase 5: Save findings (85-95%)
        logger.info(f"[{run_id}] Saving {len(all_findings)} findings...")
        save_findings(all_findings)
        update_run_progress(run_id, 95)
        
        # Phase 6: Generate report (95-100%)
        logger.info(f"[{run_id}] Generating report...")
        try:
            updated_run = get_run(run_id)
            if updated_run:
                updated_run.status = RunStatus.FINISHED
                report_builder = ReportBuilder(updated_run, all_findings)
                # Use local data folder
                data_dir = Path(os.environ.get("DATA_DIR", "./data"))
                report_path = data_dir / "runs" / run_id / "report.html"
                report_builder.save_to_file(str(report_path))
                logger.info(f"[{run_id}] Report saved to {report_path}")
        except Exception as e:
            logger.error(f"[{run_id}] Report generation error: {e}")
        
        # Done!
        update_run_status(run_id, RunStatus.FINISHED, 100)
        logger.info(f"[{run_id}] Scan completed successfully")
        
    except Exception as e:
        logger.exception(f"[{run_id}] Scan failed with error: {e}")
        update_run_status(run_id, RunStatus.FAILED, 0, str(e))


def start_scan_in_background(run: ScanRun):
    """Start a scan in the background."""
    loop = asyncio.new_event_loop()
    
    def run_async():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_scan(run))
        finally:
            loop.close()
    
    executor.submit(run_async)
    logger.info(f"Scan {run.id} submitted to background executor")


def get_report_path(run_id: str) -> Optional[Path]:
    """Get the path to the generated report for a run."""
    data_dir = Path(os.environ.get("DATA_DIR", "./data"))
    report_path = data_dir / "runs" / run_id / "report.html"
    if report_path.exists():
        return report_path
    return None


def regenerate_report(run_id: str) -> Optional[str]:
    """Regenerate the report for a completed run."""
    run = get_run(run_id)
    if not run:
        return None
    
    findings = get_findings_for_run(run_id)
    report_builder = ReportBuilder(run, findings)
    data_dir = Path(os.environ.get("DATA_DIR", "./data"))
    report_path = data_dir / "runs" / run_id / "report.html"
    return report_builder.save_to_file(str(report_path))
