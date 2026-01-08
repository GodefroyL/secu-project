/**
 * API client for communicating with the Security Scanner backend.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface ScanRequest {
  target_url: string;
  max_duration_sec?: number;
}

export interface ScanResponse {
  run_id: string;
}

export interface StatusResponse {
  status: 'queued' | 'running' | 'finished' | 'failed';
  progress: number;
  target_url?: string;
  error_message?: string;
}

export interface Asset {
  type: string;
  value: string;
}

export interface Evidence {
  details: string;
  headers: Record<string, string>;
  artifact_path?: string;
}

export interface Finding {
  id: string;
  asset: Asset;
  category: string;
  check: string;
  severity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
  summary: string;
  evidence: Evidence;
  remediation: string[];
  source: string;
  run_id: string;
}

export interface FindingsResponse {
  run_id: string;
  status: string;
  target_url: string;
  findings_count: number;
  findings: Finding[];
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new ApiError(response.status, errorData.detail || 'Request failed');
  }
  return response.json();
}

/**
 * Start a new security scan.
 */
export async function startScan(request: ScanRequest): Promise<ScanResponse> {
  const response = await fetch(`${API_BASE_URL}/runs`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      target_url: request.target_url,
      max_duration_sec: request.max_duration_sec || 300,
    }),
  });
  return handleResponse<ScanResponse>(response);
}

/**
 * Get the status of a scan.
 */
export async function getScanStatus(runId: string): Promise<StatusResponse> {
  const response = await fetch(`${API_BASE_URL}/runs/${runId}`);
  return handleResponse<StatusResponse>(response);
}

/**
 * Get the findings from a scan.
 */
export async function getScanFindings(runId: string): Promise<FindingsResponse> {
  const response = await fetch(`${API_BASE_URL}/runs/${runId}/findings`);
  return handleResponse<FindingsResponse>(response);
}

/**
 * Get the report download URL.
 */
export function getReportUrl(runId: string): string {
  return `${API_BASE_URL}/runs/${runId}/report`;
}

/**
 * Download the HTML report.
 */
export async function downloadReport(runId: string): Promise<Blob> {
  const response = await fetch(`${API_BASE_URL}/runs/${runId}/report`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new ApiError(response.status, errorData.detail || 'Failed to download report');
  }
  return response.blob();
}
