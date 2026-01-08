# 🔒 Security Scanner MVP

> Outil d'analyse automatique de sécurité web - Projet étudiant

[![Made with Next.js](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org/)
[![Made with FastAPI](https://img.shields.io/badge/FastAPI-0.109-green)](https://fastapi.tiangolo.com/)
[![OWASP ZAP](https://img.shields.io/badge/OWASP-ZAP-orange)](https://www.zaproxy.org/)

## 📋 Description

Ce projet est un MVP (Minimum Viable Product) d'outil d'analyse de sécurité web automatisé. Il permet de scanner passivement un site web pour détecter des vulnérabilités courantes sans effectuer d'attaques destructives.

### ⚠️ Avertissement Important

Ce scanner effectue uniquement des analyses **non-destructives** :
- ❌ Pas de brute force
- ❌ Pas de flood / DoS
- ❌ Pas de modification de données
- ❌ Pas de tentatives d'exploitation

**Scannez uniquement les sites dont vous êtes propriétaire ou pour lesquels vous avez une autorisation explicite.**

## 🚀 Fonctionnalités

- **Analyse TLS/SSL**
  - Vérification du certificat
  - Détection d'expiration
  - Analyse des SANs (Subject Alternative Names)
  - Vérification HSTS

- **Analyse des Headers HTTP**
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Strict-Transport-Security
  - Et plus...

- **Analyse des Cookies**
  - Flag Secure
  - Flag HttpOnly
  - Attribut SameSite

- **OWASP ZAP Baseline**
  - Scan passif automatisé
  - Détection des vulnérabilités OWASP Top 10

## 🛠️ Stack Technique

### Frontend
- Next.js 14 (App Router)
- TypeScript
- Tailwind CSS

### Backend
- Python 3.11
- FastAPI
- SQLite
- Uvicorn

### Outils de Scan
- OWASP ZAP (Docker)
- Scripts Python personnalisés

## 📦 Installation

### Prérequis

- Docker Desktop installé et lancé
- Docker Compose v2+
- 4 Go de RAM minimum (ZAP est gourmand)

### Lancement

```bash
# Cloner le projet
git clone <url-du-repo>
cd secu-project

# Lancer tous les services
docker compose up --build
```

### Accès

- **Frontend** : http://localhost:3000
- **Backend API** : http://localhost:8000
- **API Docs** : http://localhost:8000/docs
- **ZAP API** : http://localhost:8080

## 📖 Utilisation

1. Ouvrez http://localhost:3000 dans votre navigateur
2. Entrez l'URL du site à analyser
3. Cliquez sur "Lancer le scan"
4. Attendez la fin de l'analyse (2-5 minutes selon le site)
5. Consultez les résultats et téléchargez le rapport HTML

## 🔌 API Backend

### Endpoints

#### POST /runs
Créer un nouveau scan.

```json
{
  "target_url": "https://example.com",
  "max_duration_sec": 300
}
```

Réponse:
```json
{
  "run_id": "uuid"
}
```

#### GET /runs/{run_id}
Obtenir le statut d'un scan.

```json
{
  "status": "queued | running | finished | failed",
  "progress": 60,
  "target_url": "https://example.com",
  "error_message": null
}
```

#### GET /runs/{run_id}/findings
Obtenir les vulnérabilités détectées.

```json
{
  "run_id": "uuid",
  "status": "finished",
  "target_url": "https://example.com",
  "findings_count": 5,
  "findings": [...]
}
```

#### GET /runs/{run_id}/report
Télécharger le rapport HTML.

## 📄 Format des Findings

```json
{
  "id": "TLS-0001",
  "asset": {
    "type": "url",
    "value": "https://example.com"
  },
  "category": "OWASP A02",
  "check": "tls_probe",
  "severity": "High",
  "summary": "SSL certificate expires soon",
  "evidence": {
    "details": "Certificate expires in 15 days",
    "headers": {},
    "artifact_path": null
  },
  "remediation": [
    "Renew the SSL certificate",
    "Set up automated renewal"
  ],
  "source": "custom_probe",
  "run_id": "uuid"
}
```

## 📁 Structure du Projet

```
secu-project/
├── backend/
│   ├── app/
│   │   ├── main.py              # API FastAPI
│   │   ├── models.py            # Modèles de données
│   │   ├── db.py                # Couche base de données
│   │   ├── runner.py            # Orchestrateur de scan
│   │   ├── probes/
│   │   │   ├── tls_probe.py     # Analyse TLS
│   │   │   └── headers_probe.py # Analyse headers/cookies
│   │   ├── zap/
│   │   │   ├── zap_runner.py    # Exécution ZAP
│   │   │   └── zap_parser.py    # Parsing résultats ZAP
│   │   └── reporting/
│   │       └── report_builder.py # Génération rapport HTML
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── app/
│   │   ├── layout.tsx           # Layout principal
│   │   ├── page.tsx             # Page d'accueil
│   │   ├── globals.css          # Styles globaux
│   │   └── runs/[id]/page.tsx   # Page résultats
│   ├── components/
│   │   ├── FindingsTable.tsx    # Table des vulnérabilités
│   │   ├── FindingDetail.tsx    # Détail d'une vuln
│   │   └── ProgressBar.tsx      # Barre de progression
│   ├── lib/
│   │   └── api.ts               # Client API
│   ├── package.json
│   ├── tailwind.config.ts
│   └── Dockerfile
├── docker-compose.yml
├── data/                        # Volume partagé (créé auto)
└── README.md
```

## 🔍 Détails des Scans

### TLS Probe
- Connexion SSL/TLS au serveur
- Vérification de la validité du certificat
- Contrôle de la date d'expiration
- Analyse des SANs
- Vérification de la version TLS (1.2+ recommandé)
- Analyse des suites de chiffrement

### Headers Probe
- Vérification des headers de sécurité HTTP
- Analyse des cookies (Secure, HttpOnly, SameSite)
- Détection des headers d'information (Server, X-Powered-By)
- Analyse HSTS (max-age, includeSubDomains, preload)

### OWASP ZAP Baseline
- Spider passif du site
- Analyse passive des réponses
- Détection automatique des vulnérabilités
- Mapping vers OWASP Top 10

## 📊 Rapport HTML

Le rapport généré contient :
- Résumé exécutif avec comptage par sévérité
- Liste des 10 vulnérabilités les plus critiques
- Preuves techniques détaillées
- Recommandations de remédiation
- Section limitations et avertissement légal

## ⚙️ Configuration

### Variables d'environnement Backend

| Variable | Description | Défaut |
|----------|-------------|--------|
| `ZAP_API_URL` | URL de l'API ZAP | `http://zap:8080` |
| `USE_DOCKER_EXEC` | Utiliser docker exec pour ZAP | `false` |

### Variables d'environnement Frontend

| Variable | Description | Défaut |
|----------|-------------|--------|
| `NEXT_PUBLIC_API_URL` | URL de l'API backend | `http://localhost:8000` |

## 🐛 Dépannage

### ZAP ne démarre pas
```bash
# Vérifier les logs
docker compose logs zap

# Redémarrer ZAP
docker compose restart zap
```

### Le scan reste bloqué
- Vérifiez que le site cible est accessible
- Augmentez `max_duration_sec`
- Consultez les logs backend : `docker compose logs backend`

### Erreur de connexion API
- Vérifiez que le backend est lancé : http://localhost:8000/health
- Vérifiez les CORS si vous accédez depuis un autre domaine

## 🧪 Tests Manuels

```bash
# Test du backend
curl http://localhost:8000/health

# Lancer un scan
curl -X POST http://localhost:8000/runs \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'

# Vérifier le statut
curl http://localhost:8000/runs/{run_id}
```

## 📚 Ressources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [SSL Labs Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)

## 📝 Limitations

1. **Scan passif uniquement** - Pas de tests actifs d'injection
2. **Sites publics** - Pas de gestion d'authentification
3. **Single page** - Spider limité, pas de navigation JS complexe
4. **Timeout** - Maximum 30 minutes par scan
5. **Faux positifs** - Possible, validation manuelle recommandée

## 👥 Auteurs

Projet étudiant - Cours de Cybersécurité 2026

## 📄 Licence

Ce projet est destiné à un usage éducatif uniquement.

---

⚠️ **Rappel** : Utilisez cet outil de manière responsable et éthique. Ne scannez jamais un site sans autorisation.
