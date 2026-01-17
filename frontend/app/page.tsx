'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { startScan, ApiError } from '@/lib/api';

export default function HomePage() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [labMode, setLabMode] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isLabEligible = (value: string) => {
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const response = await startScan({ target_url: url, lab_mode: true });
      router.push(`/runs/${response.run_id}`);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Une erreur est survenue. Verifiez que le backend est accessible.');
      }
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      {/* Hero Section */}
      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold text-black mb-4 tracking-tight">
          Analyse de Securite Web
        </h1>
        <p className="text-lg text-gray-600">
          Scannez automatiquement les vulnerabilites de votre site web
        </p>
        <p className="text-sm text-gray-400 mt-2">
          Analyse non-destructive et passive par defaut (mode laboratoire optionnel)
        </p>
      </div>

      {/* Main Form Card */}
      <div className="card">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="url" className="block text-sm font-medium text-gray-700 mb-2">
              URL ou domaine a analyser
            </label>
            <input
              type="text"
              id="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="input-field"
              required
              disabled={isLoading}
            />
            <p className="mt-2 text-sm text-gray-500">
              Entrez l'URL complete ou le nom de domaine (HTTPS sera ajoute automatiquement)
            </p>
          </div>

          <div className="flex items-start gap-3">
            <input
              type="checkbox"
              id="lab-mode"
              checked={labMode}
              onChange={(e) => setLabMode(e.target.checked)}
              disabled={isLoading}
              className="mt-1 h-4 w-4 border-gray-300 text-black focus:ring-black"
            />
            <label htmlFor="lab-mode" className="text-sm text-gray-700">
              Activer le mode laboratoire (tests actifs). A utiliser uniquement sur un site que vous possedez ou pour
              lequel vous avez une autorisation explicite.
              {labMode && !isLabEligible(url) && (
                <span className="block text-xs text-gray-500 mt-1">
                  Le mode laboratoire est automatiquement desactive si la cible n'est pas localhost, 127.0.0.1 ou *.local.
                </span>
              )}
            </label>
          </div>

          {error && (
            <div className="bg-gray-100 border border-gray-300 text-gray-800 px-4 py-3 rounded-md">
              <p className="font-medium">Erreur</p>
              <p className="text-sm">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading || !url.trim()}
            className="btn-primary w-full flex items-center justify-center space-x-2"
          >
            {isLoading ? (
              <>
                <svg className="spinner h-5 w-5" viewBox="0 0 24 24">
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                    fill="none"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                  />
                </svg>
                <span>Lancement du scan...</span>
              </>
            ) : (
              <span>Lancer le scan</span>
            )}
          </button>
        </form>
      </div>

      {/* Info Cards */}
      <div className="grid md:grid-cols-3 gap-6 mt-12">
        <div className="card text-center">
          <h3 className="font-semibold text-black mb-2">TLS/SSL</h3>
          <p className="text-sm text-gray-600">
            Analyse des certificats, expiration, configuration HSTS
          </p>
        </div>

        <div className="card text-center">
          <h3 className="font-semibold text-black mb-2">Headers HTTP</h3>
          <p className="text-sm text-gray-600">
            Verification des en-tetes de securite (CSP, X-Frame-Options, etc.)
          </p>
        </div>

        <div className="card text-center">
          <h3 className="font-semibold text-black mb-2">Cookies</h3>
          <p className="text-sm text-gray-600">
            Analyse des attributs Secure, HttpOnly, SameSite
          </p>
        </div>
      </div>

      {/* Warning */}
      <div className="mt-12 bg-gray-100 border border-gray-300 rounded-lg p-6">
        <h3 className="font-semibold text-black mb-2">
          Avertissement Important
        </h3>
        <ul className="text-sm text-gray-700 space-y-1">
          <li>- Par defaut, le scanner effectue uniquement des analyses non-destructives</li>
          <li>- Le mode laboratoire declenche des tests actifs sur cibles locales uniquement</li>
          <li>- Scannez uniquement les sites dont vous etes proprietaire ou autorise</li>
          <li>- Projet educatif - pas un outil de pentest professionnel</li>
        </ul>
      </div>
    </div>
  );
}
