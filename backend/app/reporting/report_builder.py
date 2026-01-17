"""
HTML Report Builder.
Generates security scan reports in HTML format.
"""
import html
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.models import Finding, ScanRun, Severity


class ReportBuilder:
    """Builds HTML security scan reports."""

    def __init__(self, run: ScanRun, findings: list[Finding]):
        self.run = run
        self.findings = findings
        self.generated_at = datetime.utcnow()

    def build_html_report(self) -> str:
        """Generate a complete HTML security report."""
        severity_counts = self._count_by_severity()
        sorted_findings = self._sort_findings_by_severity()
        
        lab_mode_label = "Mode laboratoire (tests actifs)" if self.run.lab_mode else "Analyse automatisée non-destructive"
        if self.run.lab_mode:
            analysis_scope_items = """
                    <li><strong>Mode laboratoire activé</strong> : des tests actifs ont été effectués</li>
                    <li>Utilisez uniquement des cibles locales ou autorisées</li>
                    <li>Les tests actifs peuvent modifier l'état applicatif</li>
            """
            tools_list_items = """
                    <li>Tests actifs en mode laboratoire (SQLi, CSRF, least-privilege, credential stuffing, DoS simulé)</li>
            """
        else:
            analysis_scope_items = """
                    <li>Cette analyse est <strong>strictement non-destructive</strong> (passive)</li>
                    <li>Aucune tentative d'exploitation n'a été effectuée</li>
                    <li>Aucun test de brute force ou de flood</li>
                    <li>Scan limité aux vulnérabilités détectables passivement</li>
            """
            tools_list_items = ""

        info_findings = [finding for finding in sorted_findings if finding.severity == Severity.INFO]
        non_info_findings = [finding for finding in sorted_findings if finding.severity != Severity.INFO]
        info_section = ""
        if info_findings:
            info_section = f"""
        <section class="info-findings">
            <h2>Informations</h2>
            {self._render_findings_table(info_findings)}
        </section>
            """

        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Sécurité - {html.escape(self.run.target_url)}</title>
    <style>
        {self._get_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Rapport d'Analyse de Sécurité</h1>
            <p class="subtitle">{lab_mode_label}</p>
        </header>

        <section class="meta-info">
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="label">URL Cible</span>
                    <span class="value">{html.escape(self.run.target_url)}</span>
                </div>
                <div class="meta-item">
                    <span class="label">ID du Scan</span>
                    <span class="value">{html.escape(self.run.id)}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Date d'Analyse</span>
                    <span class="value">{self.generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC</span>
                </div>
                <div class="meta-item">
                    <span class="label">Statut</span>
                    <span class="value status-{self.run.status.value}">{self.run.status.value.upper()}</span>
                </div>
            </div>
        </section>

        <section class="executive-summary">
            <h2>📊 Résumé Exécutif</h2>
            <div class="summary-grid">
                <div class="summary-card critical">
                    <span class="count">{severity_counts.get('Critical', 0)}</span>
                    <span class="label">Critique</span>
                </div>
                <div class="summary-card high">
                    <span class="count">{severity_counts.get('High', 0)}</span>
                    <span class="label">Élevée</span>
                </div>
                <div class="summary-card medium">
                    <span class="count">{severity_counts.get('Medium', 0)}</span>
                    <span class="label">Moyenne</span>
                </div>
                <div class="summary-card low">
                    <span class="count">{severity_counts.get('Low', 0)}</span>
                    <span class="label">Faible</span>
                </div>
                <div class="summary-card info">
                    <span class="count">{severity_counts.get('Info', 0)}</span>
                    <span class="label">Info</span>
                </div>
            </div>
            <p class="total-findings">
                <strong>Total:</strong> {len(self.findings)} vulnérabilité(s) détectée(s)
            </p>
        </section>

        <section class="findings">
            <h2>🔍 Vulnérabilités Détectées</h2>
            {self._render_findings_table(non_info_findings)}
        </section>

        <section class="details">
            <h2>📋 Détails des Vulnérabilités</h2>
            {self._render_findings_details(non_info_findings)}
        </section>

        {info_section}

        <section class="limitations">
            <h2>⚠️ Limitations et Avertissement Légal</h2>
            <div class="warning-box">
                <h3>Portée de l'Analyse</h3>
                <ul>
                    {analysis_scope_items}
                </ul>

                <h3>Avertissement</h3>
                <p>
                    Ce rapport est généré à des fins éducatives dans le cadre d'un projet étudiant.
                    Les résultats peuvent contenir des faux positifs et ne constituent pas un audit 
                    de sécurité complet. Une analyse approfondie par des professionnels est 
                    recommandée avant toute mise en production.
                </p>

                <h3>Outils Utilisés</h3>
                <ul>
                    <li>OWASP ZAP Baseline Scan (passif)</li>
                    <li>Analyse TLS/SSL personnalisée</li>
                    <li>Analyse des en-têtes HTTP de sécurité</li>
                    <li>Analyse des cookies</li>
                    {tools_list_items}
                </ul>
            </div>
        </section>

        <footer>
            <p>
                Rapport généré automatiquement par Security Scanner MVP<br>
                Projet étudiant - {self.generated_at.year}
            </p>
        </footer>
    </div>
</body>
</html>"""

    def _count_by_severity(self) -> dict[str, int]:
        """Count findings by severity level."""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    def _sort_findings_by_severity(self) -> list[Finding]:
        """Sort findings by severity (highest first)."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))

    def _render_findings_table(self, findings: list[Finding]) -> str:
        """Render findings as an HTML table."""
        if not findings:
            return '<p class="no-findings">Aucune vulnérabilité détectée. ✅</p>'
        
        rows = ""
        for finding in findings:
            rows += f"""
            <tr class="severity-{finding.severity.value.lower()}">
                <td><code>{html.escape(finding.id)}</code></td>
                <td><span class="severity-badge {finding.severity.value.lower()}">{finding.severity.value}</span></td>
                <td>{html.escape(finding.category)}</td>
                <td>{html.escape(finding.summary[:80])}{'...' if len(finding.summary) > 80 else ''}</td>
                <td><code>{html.escape(finding.check)}</code></td>
            </tr>
            """
        
        return f"""
        <table class="findings-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Sévérité</th>
                    <th>Catégorie</th>
                    <th>Description</th>
                    <th>Source</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """

    def _render_findings_details(self, findings: list[Finding]) -> str:
        """Render detailed findings."""
        if not findings:
            return ""
        
        details = ""
        for finding in findings:
            remediation_html = "".join(
                f"<li>{html.escape(r)}</li>" for r in finding.remediation
            )
            
            details += f"""
            <div class="finding-detail severity-{finding.severity.value.lower()}">
                <div class="finding-header">
                    <span class="finding-id">{html.escape(finding.id)}</span>
                    <span class="severity-badge {finding.severity.value.lower()}">{finding.severity.value}</span>
                    <span class="finding-category">{html.escape(finding.category)}</span>
                </div>
                
                <h3>{html.escape(finding.summary)}</h3>
                
                <div class="finding-meta">
                    <p><strong>Asset:</strong> <code>{html.escape(finding.asset.value)}</code></p>
                    <p><strong>Source:</strong> {html.escape(finding.check)} ({html.escape(finding.source)})</p>
                </div>
                
                <div class="finding-evidence">
                    <h4>Preuves Techniques</h4>
                    <pre>{html.escape(finding.evidence.details[:1000])}{'...' if len(finding.evidence.details) > 1000 else ''}</pre>
                </div>
                
                <div class="finding-remediation">
                    <h4>Recommandations</h4>
                    <ul>
                        {remediation_html}
                    </ul>
                </div>
            </div>
            """
        
        return details

    def _get_styles(self) -> str:
        """Return CSS styles for the report."""
        return """
        :root {
            --color-critical: #dc2626;
            --color-high: #ea580c;
            --color-medium: #ca8a04;
            --color-low: #2563eb;
            --color-info: #64748b;
            --color-bg: #f8fafc;
            --color-card: #ffffff;
            --color-border: #e2e8f0;
            --color-text: #1e293b;
            --color-text-muted: #64748b;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--color-bg);
            color: var(--color-text);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        header {
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: linear-gradient(135deg, #1e3a5f, #2d5a87);
            color: white;
            border-radius: 1rem;
        }
        
        header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        header .subtitle {
            opacity: 0.9;
            font-size: 1.1rem;
        }
        
        section {
            background: var(--color-card);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        h2 {
            color: var(--color-text);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--color-border);
        }
        
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        
        .meta-item .label {
            font-size: 0.875rem;
            color: var(--color-text-muted);
            margin-bottom: 0.25rem;
        }
        
        .meta-item .value {
            font-weight: 600;
            word-break: break-all;
        }
        
        .status-finished { color: #16a34a; }
        .status-failed { color: var(--color-critical); }
        .status-running { color: var(--color-medium); }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .summary-card {
            text-align: center;
            padding: 1rem;
            border-radius: 0.5rem;
            color: white;
        }
        
        .summary-card.critical { background: var(--color-critical); }
        .summary-card.high { background: var(--color-high); }
        .summary-card.medium { background: var(--color-medium); }
        .summary-card.low { background: var(--color-low); }
        .summary-card.info { background: var(--color-info); }
        
        .summary-card .count {
            display: block;
            font-size: 2rem;
            font-weight: bold;
        }
        
        .total-findings {
            text-align: center;
            font-size: 1.1rem;
        }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        
        .findings-table th,
        .findings-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--color-border);
        }
        
        .findings-table th {
            background: var(--color-bg);
            font-weight: 600;
        }
        
        .findings-table tbody tr:hover {
            background: var(--color-bg);
        }
        
        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }
        
        .severity-badge.critical { background: var(--color-critical); }
        .severity-badge.high { background: var(--color-high); }
        .severity-badge.medium { background: var(--color-medium); }
        .severity-badge.low { background: var(--color-low); }
        .severity-badge.info { background: var(--color-info); }
        
        .finding-detail {
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-radius: 0.5rem;
            border-left: 4px solid var(--color-border);
            background: var(--color-bg);
        }
        
        .finding-detail.severity-critical { border-left-color: var(--color-critical); }
        .finding-detail.severity-high { border-left-color: var(--color-high); }
        .finding-detail.severity-medium { border-left-color: var(--color-medium); }
        .finding-detail.severity-low { border-left-color: var(--color-low); }
        .finding-detail.severity-info { border-left-color: var(--color-info); }
        
        .finding-header {
            display: flex;
            gap: 1rem;
            align-items: center;
            margin-bottom: 0.75rem;
        }
        
        .finding-id {
            font-family: monospace;
            background: var(--color-card);
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
        }
        
        .finding-detail h3 {
            margin-bottom: 1rem;
        }
        
        .finding-detail h4 {
            font-size: 0.875rem;
            color: var(--color-text-muted);
            margin: 1rem 0 0.5rem;
        }
        
        .finding-evidence pre {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            font-size: 0.875rem;
            white-space: pre-wrap;
            word-break: break-word;
        }
        
        .finding-remediation ul {
            list-style-position: inside;
            padding-left: 0;
        }
        
        .finding-remediation li {
            margin-bottom: 0.5rem;
        }
        
        .warning-box {
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 0.5rem;
            padding: 1.5rem;
        }
        
        .warning-box h3 {
            color: #92400e;
            margin: 1rem 0 0.5rem;
        }
        
        .warning-box h3:first-child {
            margin-top: 0;
        }
        
        .warning-box ul {
            margin-left: 1.5rem;
            margin-bottom: 1rem;
        }
        
        .no-findings {
            text-align: center;
            color: #16a34a;
            font-size: 1.25rem;
            padding: 2rem;
        }
        
        footer {
            text-align: center;
            padding: 2rem;
            color: var(--color-text-muted);
            font-size: 0.875rem;
        }
        
        code {
            font-family: 'Consolas', 'Monaco', monospace;
            background: var(--color-bg);
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.875rem;
        }
        
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: repeat(3, 1fr);
            }
            
            .container {
                padding: 1rem;
            }
            
            .findings-table {
                font-size: 0.875rem;
            }
        }
        
        @media print {
            body {
                background: white;
            }
            
            .container {
                max-width: none;
            }
            
            section {
                break-inside: avoid;
            }
        }
        """

    def save_to_file(self, output_path: str) -> str:
        """Save the report to a file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        html_content = self.build_html_report()
        path.write_text(html_content, encoding="utf-8")
        
        return str(path)
