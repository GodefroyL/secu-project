interface ProgressBarProps {
  progress: number;
  status: 'queued' | 'running' | 'finished' | 'failed';
}

export default function ProgressBar({ progress, status }: ProgressBarProps) {
  const getPhaseText = (progress: number) => {
    if (progress < 30) return 'Analyse TLS/SSL en cours...';
    if (progress < 60) return 'Analyse des en-tetes HTTP...';
    if (progress < 80) return 'Analyse des cookies...';
    if (progress < 90) return 'Sauvegarde des resultats...';
    return 'Generation du rapport...';
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-600">
          {status === 'queued' ? 'En attente de demarrage...' : getPhaseText(progress)}
        </span>
        <span className="font-semibold text-black">{progress}%</span>
      </div>

      <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ease-out ${
            status === 'running'
              ? 'bg-black progress-bar-animated'
              : 'bg-black'
          }`}
          style={{ width: `${Math.max(progress, 2)}%` }}
        />
      </div>

      <div className="grid grid-cols-4 gap-2 text-xs text-center">
        {[
          { label: 'TLS', threshold: 30 },
          { label: 'Headers', threshold: 60 },
          { label: 'Cookies', threshold: 80 },
          { label: 'Rapport', threshold: 100 },
        ].map((phase) => (
          <div
            key={phase.label}
            className={`py-2 rounded border ${
              progress >= phase.threshold
                ? 'bg-black text-white border-black'
                : progress >= phase.threshold - 30
                ? 'bg-gray-200 text-black border-gray-300'
                : 'bg-white text-gray-400 border-gray-200'
            }`}
          >
            {progress >= phase.threshold ? 'OK ' : ''}
            {phase.label}
          </div>
        ))}
      </div>

      {status === 'running' && (
        <p className="text-sm text-gray-500 text-center">
          Le scan peut prendre quelques minutes selon la taille du site...
        </p>
      )}
    </div>
  );
}
