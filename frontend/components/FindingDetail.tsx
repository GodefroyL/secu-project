import { Finding } from '@/lib/api';

interface FindingDetailProps {
  finding: Finding;
}

export default function FindingDetail({ finding }: FindingDetailProps) {
  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'border-red-600 bg-red-50';
      case 'High':
        return 'border-orange-500 bg-orange-50';
      case 'Medium':
        return 'border-yellow-500 bg-yellow-50';
      case 'Low':
        return 'border-blue-500 bg-blue-50';
      default:
        return 'border-gray-200 bg-gray-50';
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'bg-red-600 text-white';
      case 'High':
        return 'bg-orange-500 text-white';
      case 'Medium':
        return 'bg-yellow-500 text-black';
      case 'Low':
        return 'bg-blue-500 text-white';
      default:
        return 'bg-gray-200 text-black border border-gray-300';
    }
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

  return (
    <div className={`border-l-4 p-6 rounded-r-lg ${getSeverityClass(finding.severity)}`}>
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <code className="bg-white px-3 py-1 rounded border border-gray-300 text-sm font-mono">
          {finding.id}
        </code>
        <span
          className={`px-3 py-1 rounded text-sm font-semibold ${getSeverityBadgeClass(
            finding.severity
          )}`}
        >
          {getSeverityLabel(finding.severity)}
        </span>
        <span className="text-gray-600 text-sm">{finding.category}</span>
      </div>

      {/* Summary */}
      <h3 className="text-lg font-semibold text-black mb-4">
        {finding.summary}
      </h3>

      {/* Asset */}
      <div className="mb-4">
        <h4 className="text-sm font-semibold text-black mb-1">Asset affecte</h4>
        <p className="text-sm">
          <span className="text-gray-500">{finding.asset.type}:</span>{' '}
          <code className="bg-white px-2 py-1 rounded border border-gray-300 text-sm break-all">
            {finding.asset.value}
          </code>
        </p>
      </div>

      {/* Source */}
      <div className="mb-4">
        <h4 className="text-sm font-semibold text-black mb-1">Source</h4>
        <p className="text-sm text-gray-600">
          {finding.source} / {finding.check}
        </p>
      </div>

      {/* Evidence */}
      <div className="mb-4">
        <h4 className="text-sm font-semibold text-black mb-2">
          Preuves techniques
        </h4>
        <pre className="bg-black text-gray-100 p-4 rounded-lg overflow-x-auto text-sm whitespace-pre-wrap">
          {finding.evidence.details || 'Aucun detail disponible'}
        </pre>
      </div>

      {/* Headers if available */}
      {finding.evidence.headers && Object.keys(finding.evidence.headers).length > 0 && (
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-black mb-2">
            En-tetes HTTP
          </h4>
          <div className="bg-white rounded border border-gray-300 p-4 overflow-x-auto">
            <table className="text-sm">
              <tbody>
                {Object.entries(finding.evidence.headers).map(([key, value]) => (
                  <tr key={key}>
                    <td className="pr-4 font-mono text-gray-600">{key}:</td>
                    <td className="font-mono text-black break-all">{value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Remediation */}
      <div>
        <h4 className="text-sm font-semibold text-black mb-2">
          Recommandations
        </h4>
        <ul className="list-disc list-inside space-y-1">
          {finding.remediation.map((rec, index) => (
            <li key={index} className="text-sm text-gray-700">
              {rec}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
