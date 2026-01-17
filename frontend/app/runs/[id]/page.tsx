'use client';

import { useEffect, useState, useCallback } from 'react';
import { useParams } from 'next/navigation';
import { 
  getScanStatus, 
  getScanFindings, 
  getReportUrl,
  StatusResponse, 
  Finding,
  ApiError 
} from '@/lib/api';
import FindingsTable from '@/components/FindingsTable';
import FindingDetail from '@/components/FindingDetail';
import ProgressBar from '@/components/ProgressBar';

export default function RunPage() {
  const params = useParams();
  const runId = params.id as string;

  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isPolling, setIsPolling] = useState(true);

  const fetchStatus = useCallback(async () => {
    try {
      const statusData = await getScanStatus(runId);
      setStatus(statusData);

      if (statusData.status === 'finished' || statusData.status === 'failed') {
        setIsPolling(false);
        
        if (statusData.status === 'finished') {
          const findingsData = await getScanFindings(runId);
          setFindings(findingsData.findings);
        }
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Impossible de recuperer le statut du scan.');
      }
      setIsPolling(false);
    }
  }, [runId]);

  useEffect(() => {
    fetchStatus();

    if (isPolling) {
      const interval = setInterval(fetchStatus, 2000);
      return () => clearInterval(interval);
    }
  }, [fetchStatus, isPolling]);

  const getStatusText = () => {
    switch (status?.status) {
      case 'queued':
        return 'En attente';
      case 'running':
        return 'Scan en cours...';
      case 'finished':
        return 'Scan termine';
      case 'failed':
        return 'Echec du scan';
      default:
        return 'Statut inconnu';
    }
  };

  const countBySeverity = () => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    findings.forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    return counts;
  };

  const getSeverityLabel = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'Critique';
      case 'High': return 'Elevee';
      case 'Medium': return 'Moyenne';
      case 'Low': return 'Faible';
      case 'Info': return 'Info';
      default: return severity;
    }
  };

  if (error) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="card bg-gray-100 border-gray-300">
          <h2 className="text-xl font-bold text-black mb-2">Erreur</h2>
          <p className="text-gray-700">{error}</p>
          <a href="/" className="btn-primary inline-block mt-4">
            Retour a l'accueil
          </a>
        </div>
      </div>
    );
  }

  if (!status) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="spinner h-12 w-12 border-4 border-black border-t-transparent rounded-full mx-auto mb-4"></div>
          <p className="text-gray-600">Chargement...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <a href="/" className="text-gray-600 hover:text-black text-sm mb-2 inline-block">
            &larr; Nouveau scan
          </a>
          <h1 className="text-2xl font-bold text-black">
            {getStatusText()}
          </h1>
          <p className="text-gray-600 mt-1">
            <span className="font-medium">Cible:</span>{' '}
            <code className="bg-gray-100 px-2 py-1 rounded text-sm border border-gray-200">
              {status.target_url}
            </code>
          </p>
          <p className="text-gray-500 text-sm mt-1">
            <span className="font-medium">ID:</span> {runId}
          </p>
          {typeof status.lab_mode === 'boolean' && (
            <p className="text-gray-500 text-sm mt-1">
              <span className="font-medium">Mode:</span>{' '}
              {status.lab_mode ? 'Laboratoire (tests actifs)' : 'Passif'}
            </p>
          )}
        </div>

        {status.status === 'finished' && (
          <a
            href={getReportUrl(runId)}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-primary inline-flex items-center space-x-2"
          >
            <span>Telecharger le rapport</span>
          </a>
        )}
      </div>

      {/* Progress Bar */}
      {(status.status === 'queued' || status.status === 'running') && (
        <div className="card">
          <ProgressBar progress={status.progress} status={status.status} />
        </div>
      )}

      {/* Error Message */}
      {status.status === 'failed' && status.error_message && (
        <div className="card bg-gray-100 border-gray-300">
          <h3 className="font-semibold text-black mb-2">Message d'erreur</h3>
          <p className="text-gray-700">{status.error_message}</p>
        </div>
      )}

      {/* Results */}
      {status.status === 'finished' && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {Object.entries(countBySeverity()).map(([severity, count]) => (
              <div
                key={severity}
                className={`card text-center severity-${severity.toLowerCase()}`}
              >
                <div className="text-3xl font-bold">{count}</div>
                <div className="text-sm font-medium">{getSeverityLabel(severity)}</div>
              </div>
            ))}
          </div>

          {/* Findings Table */}
          <div className="card">
            <h2 className="text-xl font-bold text-black mb-4">
              Vulnerabilites detectees ({findings.length})
            </h2>
            {findings.length > 0 ? (
              <FindingsTable
                findings={findings}
                onSelectFinding={setSelectedFinding}
                selectedFinding={selectedFinding}
              />
            ) : (
              <div className="text-center py-12 text-gray-500">
                <p className="text-lg font-medium">Aucune vulnerabilite detectee</p>
                <p className="text-sm mt-2">
                  Le scan n'a pas trouve de problemes de securite evidents.
                </p>
              </div>
            )}
          </div>

          {/* Finding Detail */}
          {selectedFinding && (
            <div className="card">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-black">
                  Details de la vulnerabilite
                </h2>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="text-gray-500 hover:text-black text-xl font-bold"
                >
                  X
                </button>
              </div>
              <FindingDetail finding={selectedFinding} />
            </div>
          )}
        </>
      )}
    </div>
  );
}
