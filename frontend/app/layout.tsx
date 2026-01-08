import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Security Scanner - Analyse de Securite Web',
  description: 'Outil d\'analyse automatique de securite web - Projet etudiant',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="fr">
      <body className="min-h-screen bg-white">
        <nav className="bg-black text-white border-b border-gray-800">
          <div className="max-w-7xl mx-auto px-4 py-4">
            <div className="flex items-center justify-between">
              <a href="/" className="flex items-center space-x-2">
                <span className="text-xl font-bold tracking-tight">SECURITY SCANNER</span>
              </a>
              <span className="text-sm text-gray-400">MVP - Projet Etudiant</span>
            </div>
          </div>
        </nav>
        <main className="max-w-7xl mx-auto px-4 py-8">
          {children}
        </main>
        <footer className="bg-black text-gray-400 text-center py-6 mt-12 border-t border-gray-800">
          <p className="text-sm">Security Scanner MVP - Projet Etudiant 2026</p>
          <p className="text-xs mt-1 text-gray-500">Analyse non-destructive uniquement</p>
        </footer>
      </body>
    </html>
  );
}
