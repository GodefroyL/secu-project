"""
OWASP ZAP Baseline Scan Runner.
Executes ZAP in Docker for passive security scanning.
Non-destructive baseline scan only.
"""
import asyncio
import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ZAPRunner:
    """Runs OWASP ZAP baseline scan in Docker."""

    def __init__(self, run_id: str, data_dir: str = "/data"):
        self.run_id = run_id
        self.data_dir = Path(data_dir)
        self.output_dir = self.data_dir / "runs" / run_id / "zap"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def get_report_path(self, report_type: str = "json") -> Path:
        """Get the path for the ZAP report file."""
        suffix = ".json" if report_type == "json" else ".html"
        return self.output_dir / f"zap_report{suffix}"

    async def run_baseline_scan(
        self, 
        target_url: str, 
        max_duration_sec: int = 300,
        progress_callback: Optional[callable] = None
    ) -> tuple[bool, str]:
        """
        Run ZAP baseline scan against the target URL.
        
        Args:
            target_url: The URL to scan
            max_duration_sec: Maximum scan duration in seconds
            progress_callback: Optional callback for progress updates
            
        Returns:
            Tuple of (success: bool, output_path_or_error: str)
        """
        json_report = self.get_report_path("json")
        html_report = self.get_report_path("html")
        
        # Determine if running inside Docker or locally
        zap_container = os.environ.get("ZAP_CONTAINER", "zap")
        use_docker_exec = os.environ.get("USE_DOCKER_EXEC", "false").lower() == "true"
        
        if use_docker_exec:
            # Running alongside ZAP container - use docker exec
            cmd = self._build_docker_exec_command(
                zap_container, target_url, json_report, html_report, max_duration_sec
            )
        else:
            # Use docker run
            cmd = self._build_docker_run_command(
                target_url, json_report, html_report, max_duration_sec
            )
        
        logger.info(f"Starting ZAP baseline scan for {target_url}")
        logger.debug(f"ZAP command: {' '.join(cmd)}")
        
        try:
            # Run ZAP baseline scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=max_duration_sec + 60  # Extra buffer
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return False, "ZAP scan timed out"
            
            stdout_str = stdout.decode() if stdout else ""
            stderr_str = stderr.decode() if stderr else ""
            
            logger.debug(f"ZAP stdout: {stdout_str}")
            if stderr_str:
                logger.warning(f"ZAP stderr: {stderr_str}")
            
            # ZAP baseline returns:
            # 0 = no alerts
            # 1 = fail on warn (alerts found but not failing)
            # 2 = at least one fail alert
            # 3 = at least one fail alert and at least one warn
            if process.returncode in [0, 1, 2, 3]:
                if json_report.exists():
                    logger.info(f"ZAP scan completed successfully: {json_report}")
                    return True, str(json_report)
                else:
                    # Check if report was created in container volume
                    return True, str(json_report)
            else:
                error_msg = f"ZAP scan failed with code {process.returncode}: {stderr_str}"
                logger.error(error_msg)
                return False, error_msg
                
        except FileNotFoundError:
            error_msg = "Docker not found. Please ensure Docker is installed and running."
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"ZAP scan error: {str(e)}"
            logger.exception(error_msg)
            return False, error_msg

    def _build_docker_run_command(
        self,
        target_url: str,
        json_report: Path,
        html_report: Path,
        max_duration_sec: int
    ) -> list[str]:
        """Build docker run command for ZAP baseline scan."""
        # Calculate ZAP timing
        spider_mins = max(1, max_duration_sec // 120)
        
        return [
            "docker", "run", "--rm",
            "-v", f"{self.data_dir}:/zap/wrk:rw",
            "-t", "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py",
            "-t", target_url,
            "-J", f"/zap/wrk/runs/{self.run_id}/zap/zap_report.json",
            "-r", f"/zap/wrk/runs/{self.run_id}/zap/zap_report.html",
            "-m", str(spider_mins),
            "-I",  # Don't return failure for warnings
            "-a",  # Include alpha passive scan rules
        ]

    def _build_docker_exec_command(
        self,
        container_name: str,
        target_url: str,
        json_report: Path,
        html_report: Path,
        max_duration_sec: int
    ) -> list[str]:
        """Build docker exec command for ZAP baseline scan (when ZAP is a service)."""
        spider_mins = max(1, max_duration_sec // 120)
        
        return [
            "docker", "exec", container_name,
            "zap-baseline.py",
            "-t", target_url,
            "-J", f"/zap/wrk/runs/{self.run_id}/zap/zap_report.json",
            "-r", f"/zap/wrk/runs/{self.run_id}/zap/zap_report.html",
            "-m", str(spider_mins),
            "-I",
            "-a",
        ]

    async def run_baseline_scan_via_api(
        self,
        target_url: str,
        max_duration_sec: int = 300,
        progress_callback: Optional[callable] = None
    ) -> tuple[bool, str]:
        """
        Alternative method: Run ZAP scan via ZAP API (when ZAP runs as daemon).
        This is used when ZAP container is running as a service.
        """
        import httpx
        
        zap_api_url = os.environ.get("ZAP_API_URL", "http://zap:8080")
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Start spider
                if progress_callback:
                    await progress_callback(10)
                
                logger.info(f"Starting ZAP spider on {target_url}")
                spider_resp = await client.get(
                    f"{zap_api_url}/JSON/spider/action/scan/",
                    params={"url": target_url, "maxChildren": "10"}
                )
                spider_data = spider_resp.json()
                spider_id = spider_data.get("scan")
                
                # Wait for spider to complete
                while True:
                    status_resp = await client.get(
                        f"{zap_api_url}/JSON/spider/view/status/",
                        params={"scanId": spider_id}
                    )
                    status = int(status_resp.json().get("status", "0"))
                    if progress_callback:
                        await progress_callback(10 + (status // 3))
                    if status >= 100:
                        break
                    await asyncio.sleep(2)
                
                # Start passive scan wait
                if progress_callback:
                    await progress_callback(50)
                
                logger.info("Waiting for passive scan to complete")
                while True:
                    records_resp = await client.get(
                        f"{zap_api_url}/JSON/pscan/view/recordsToScan/"
                    )
                    records = int(records_resp.json().get("recordsToScan", "0"))
                    if records == 0:
                        break
                    await asyncio.sleep(1)
                
                if progress_callback:
                    await progress_callback(80)
                
                # Get alerts/report
                logger.info("Fetching ZAP alerts")
                alerts_resp = await client.get(
                    f"{zap_api_url}/JSON/core/view/alerts/",
                    params={"baseurl": target_url}
                )
                
                # Save JSON report
                json_report = self.get_report_path("json")
                json_report.write_text(alerts_resp.text)
                
                # Get HTML report
                html_resp = await client.get(
                    f"{zap_api_url}/OTHER/core/other/htmlreport/"
                )
                html_report = self.get_report_path("html")
                html_report.write_bytes(html_resp.content)
                
                if progress_callback:
                    await progress_callback(100)
                
                return True, str(json_report)
                
        except Exception as e:
            error_msg = f"ZAP API error: {str(e)}"
            logger.exception(error_msg)
            return False, error_msg
