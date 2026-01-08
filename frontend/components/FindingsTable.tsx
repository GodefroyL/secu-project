import { Finding } from '@/lib/api';

interface FindingsTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  selectedFinding: Finding | null;
}

export default function FindingsTable({
  findings,
  onSelectFinding,
  selectedFinding,
}: FindingsTableProps) {
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

  const sortedFindings = [...findings].sort((a, b) => {
    const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return (
      (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
    );
  });

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="bg-gray-50 border-b border-gray-200">
            <th className="px-4 py-3 text-left text-sm font-semibold text-black">
              ID
            </th>
            <th className="px-4 py-3 text-left text-sm font-semibold text-black">
              Severite
            </th>
            <th className="px-4 py-3 text-left text-sm font-semibold text-black">
              Categorie
            </th>
            <th className="px-4 py-3 text-left text-sm font-semibold text-black">
              Description
            </th>
            <th className="px-4 py-3 text-left text-sm font-semibold text-black">
              Source
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {sortedFindings.map((finding) => (
            <tr
              key={finding.id}
              onClick={() => onSelectFinding(finding)}
              className={`cursor-pointer transition-colors hover:bg-gray-50 ${
                selectedFinding?.id === finding.id ? 'bg-gray-100' : ''
              }`}
            >
              <td className="px-4 py-3">
                <code className="text-sm bg-gray-100 px-2 py-1 rounded border border-gray-200">
                  {finding.id}
                </code>
              </td>
              <td className="px-4 py-3">
                <span
                  className={`inline-block px-3 py-1 rounded text-xs font-semibold ${getSeverityBadgeClass(
                    finding.severity
                  )}`}
                >
                  {getSeverityLabel(finding.severity)}
                </span>
              </td>
              <td className="px-4 py-3 text-sm text-gray-600">
                {finding.category}
              </td>
              <td className="px-4 py-3 text-sm text-black max-w-md">
                <span className="line-clamp-2">{finding.summary}</span>
              </td>
              <td className="px-4 py-3">
                <code className="text-xs bg-gray-100 px-2 py-1 rounded border border-gray-200">
                  {finding.check}
                </code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
