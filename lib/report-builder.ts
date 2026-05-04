import type { Analysis, Component, ComponentVulnerability } from '@prisma/client';

export interface FullAnalysis extends Analysis {
  components: (Component & { vulnerabilities: ComponentVulnerability[] })[];
}

export function buildJsonReport(analysis: FullAnalysis) {
  return {
    schemaVersion: '1.0',
    generatedAt: new Date().toISOString(),
    analysis: {
      id: analysis.id,
      filename: analysis.filename,
      format: analysis.format,
      specVersion: analysis.specVersion,
      isDemo: analysis.isDemo,
      createdAt: analysis.createdAt,
      summary: {
        componentCount: analysis.componentCount,
        vulnerableCount: analysis.vulnerableCount,
        maliciousCount: analysis.maliciousCount,
        riskScore: analysis.riskScore,
      },
    },
    components: analysis.components.map((c) => ({
      purl: c.purl,
      name: c.name,
      version: c.version,
      ecosystem: c.ecosystem,
      licenses: c.licenses,
      vulnCount: c.vulnCount,
      maxSeverity: c.maxSeverity,
      maxEpss: c.maxEpss,
      isMalicious: c.isMalicious,
      maliciousReason: c.maliciousReason,
      maliciousDetail: c.maliciousDetail,
      hasKev: c.hasKev,
      scorecardScore: c.scorecardScore,
      recommendedFix: c.recommendedFix,
      riskScore: c.riskScore,
      riskBand: c.riskBand,
      vulnerabilities: c.vulnerabilities.map((v) => ({
        id: v.vulnId,
        primaryCve: v.primaryCve,
        aliases: v.aliases,
        cweIds: v.cweIds,
        severity: v.severity,
        cvssScore: v.cvssScore,
        epssScore: v.epssScore,
        epssPercentile: v.epssPercentile,
        isKev: v.isKev,
        kevDueDate: v.kevDueDate,
        isMalicious: v.isMalicious,
      })),
    })),
  };
}

export function buildCycloneDxVex(analysis: FullAnalysis) {
  const vulnerabilities = [];
  for (const c of analysis.components) {
    for (const v of c.vulnerabilities) {
      const advisories = [];
      if (v.primaryCve) {
        advisories.push({ url: `https://nvd.nist.gov/vuln/detail/${v.primaryCve}` });
      }
      vulnerabilities.push({
        id: v.vulnId,
        source: { name: v.vulnId.startsWith('GHSA') ? 'GitHub Advisory' : v.vulnId.startsWith('CVE') ? 'NVD' : 'OSV', url: 'https://osv.dev' },
        ratings: v.cvssScore !== null
          ? [{ source: { name: 'NVD' }, score: v.cvssScore, severity: v.severity.toLowerCase(), method: 'CVSSv3' }]
          : [],
        cwes: Array.isArray(v.cweIds)
          ? (v.cweIds as string[]).map((c) => parseInt(c.replace(/^CWE-/, ''), 10)).filter((n) => !isNaN(n))
          : [],
        advisories,
        affects: [{ ref: c.purl }],
        analysis: {
          state: 'in_triage',
          detail: v.isKev
            ? `CISA KEV — actively exploited. ${v.kevDueDate ? `Federal due date: ${new Date(v.kevDueDate).toISOString().split('T')[0]}.` : ''}`
            : v.isMalicious ? 'Malicious package — remove immediately' : '',
        },
      });
    }
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${analysis.id}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'sbom-vuln-analyzer', name: 'vex-export', version: '1.0' }],
      component: { type: 'application', name: analysis.filename, 'bom-ref': analysis.id },
    },
    components: analysis.components.map((c) => ({
      type: 'library',
      'bom-ref': c.purl,
      name: c.name,
      version: c.version,
      purl: c.purl,
      licenses: Array.isArray(c.licenses)
        ? (c.licenses as string[]).map((l) => ({ license: { name: l } }))
        : [],
    })),
    vulnerabilities,
  };
}

export function buildHtmlReport(analysis: FullAnalysis): string {
  const created = new Date(analysis.createdAt).toLocaleString();
  const vulnRows: string[] = [];
  for (const c of analysis.components) {
    for (const v of c.vulnerabilities) {
      const cwes = Array.isArray(v.cweIds) ? (v.cweIds as string[]).join(', ') : '';
      vulnRows.push(`
        <tr class="sev-${(v.severity ?? 'NONE').toLowerCase()}">
          <td>${escape(c.name)}</td>
          <td>${escape(c.version)}</td>
          <td>${escape(c.ecosystem ?? '—')}</td>
          <td>${escape(v.vulnId)}${v.primaryCve && v.primaryCve !== v.vulnId ? `<br/><small>${escape(v.primaryCve)}</small>` : ''}</td>
          <td><strong>${escape(v.severity ?? 'NONE')}</strong></td>
          <td>${v.cvssScore?.toFixed(1) ?? '—'}</td>
          <td>${v.epssScore !== null ? `${(v.epssScore * 100).toFixed(2)}%` : '—'}</td>
          <td>${cwes}</td>
          <td>${v.isKev ? '<span class="kev">KEV</span>' : ''}${v.isMalicious ? '<span class="mal">MALICIOUS</span>' : ''}</td>
          <td>${escape(c.recommendedFix ?? '—')}</td>
        </tr>`);
    }
  }
  if (vulnRows.length === 0) {
    vulnRows.push(`<tr><td colspan="10" style="text-align:center;padding:24px;">No known vulnerabilities found.</td></tr>`);
  }

  const malicious = analysis.components.filter((c) => c.isMalicious);
  const kev = analysis.components.filter((c) => c.hasKev);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Vulnerability report — ${escape(analysis.filename)}</title>
<style>
  @page { size: A4; margin: 18mm; }
  body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; color: #1a1a1a; margin: 0; padding: 24px; }
  h1 { margin: 0 0 4px; }
  h2 { margin-top: 32px; border-bottom: 2px solid #333; padding-bottom: 4px; }
  .meta { color: #555; font-size: 13px; margin-bottom: 24px; }
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 24px 0; }
  .stat { border: 1px solid #ddd; border-radius: 6px; padding: 12px; }
  .stat-label { color: #666; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-value { font-size: 24px; font-weight: 600; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 12px; }
  th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #f4f4f4; font-weight: 600; }
  .sev-critical { background: rgba(255, 77, 109, 0.08); }
  .sev-high { background: rgba(255, 140, 66, 0.08); }
  .kev { display: inline-block; padding: 1px 6px; background: #c00; color: #fff; font-size: 10px; font-weight: 700; border-radius: 3px; margin-right: 4px; }
  .mal { display: inline-block; padding: 1px 6px; background: #800; color: #fff; font-size: 10px; font-weight: 700; border-radius: 3px; }
  .alert { padding: 10px 14px; border-left: 4px solid #c00; background: rgba(255, 77, 109, 0.08); margin: 12px 0; border-radius: 4px; }
  small { color: #777; }
  .footer { margin-top: 48px; padding-top: 12px; border-top: 1px solid #ddd; color: #777; font-size: 11px; }
  @media print { .no-print { display: none; } }
</style>
</head>
<body>
  <div class="no-print" style="text-align:right;margin-bottom:8px;">
    <button onclick="window.print()" style="padding:6px 14px;cursor:pointer;">Print / Save as PDF</button>
  </div>
  <h1>Vulnerability Report</h1>
  <div class="meta">
    <strong>${escape(analysis.filename)}</strong> · ${escape(analysis.format)} ${escape(analysis.specVersion)} ·
    Generated ${new Date().toLocaleString()} · Analysis created ${created}
    ${analysis.isDemo ? ' · DEMO' : ''}
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-label">Risk score</div><div class="stat-value">${analysis.riskScore}</div></div>
    <div class="stat"><div class="stat-label">Components</div><div class="stat-value">${analysis.componentCount}</div></div>
    <div class="stat"><div class="stat-label">Vulnerable</div><div class="stat-value">${analysis.vulnerableCount}</div></div>
    <div class="stat"><div class="stat-label">Malicious</div><div class="stat-value">${analysis.maliciousCount}</div></div>
    <div class="stat"><div class="stat-label">KEV components</div><div class="stat-value">${kev.length}</div></div>
  </div>

  ${kev.length > 0 ? `<div class="alert"><strong>${kev.length} component${kev.length > 1 ? 's' : ''} contain CISA Known Exploited Vulnerabilities.</strong> Patch immediately.</div>` : ''}
  ${malicious.length > 0 ? `<div class="alert"><strong>${malicious.length} suspicious package${malicious.length > 1 ? 's' : ''} detected.</strong> ${malicious.map((c) => `${c.name}@${c.version}`).join(', ')}</div>` : ''}

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Component</th><th>Version</th><th>Ecosystem</th><th>Vuln ID</th>
        <th>Severity</th><th>CVSS</th><th>EPSS</th><th>CWE</th><th>Flags</th><th>Fix</th>
      </tr>
    </thead>
    <tbody>${vulnRows.join('')}</tbody>
  </table>

  <div class="footer">
    Generated by SBOM Vulnerability Analyzer. Data sources: OSV.dev, CISA KEV, FIRST.org EPSS, NVD, deps.dev, OpenSSF Scorecard.
  </div>
</body>
</html>`;
}

function escape(s: string | null | undefined): string {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
