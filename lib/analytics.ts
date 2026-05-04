import { parseCvssVector } from './cvss';
import type { OsvVuln, Severity, SeverityDistribution } from './types';

const OSV_DB_SEVERITY: Record<string, Severity> = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MODERATE: 'MEDIUM',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
};

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  NONE: 0,
};

export function emptyDistribution(): SeverityDistribution {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
}

export function bucketByCvss(score: number | null): Severity {
  if (score === null || isNaN(score) || score <= 0) return 'NONE';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

export function extractCvssScore(vuln: OsvVuln): { score: number | null; vector: string | null } {
  if (!vuln.severity || vuln.severity.length === 0) {
    const fromDb = severityFromDatabaseSpecific(vuln);
    return fromDb !== null ? { score: fromDb, vector: null } : { score: null, vector: null };
  }
  let bestScore: number | null = null;
  let bestVector: string | null = null;
  for (const s of vuln.severity) {
    const parsed = parseCvssVector(s.score ?? '');
    if (parsed === null) continue;
    if (bestScore === null || parsed > bestScore) {
      bestScore = parsed;
      bestVector = s.score ?? null;
    }
  }
  if (bestScore !== null) return { score: bestScore, vector: bestVector };

  const fromDb = severityFromDatabaseSpecific(vuln);
  return fromDb !== null
    ? { score: fromDb, vector: vuln.severity[0]?.score ?? null }
    : { score: null, vector: vuln.severity[0]?.score ?? null };
}

function severityFromDatabaseSpecific(vuln: OsvVuln): number | null {
  const ds = (vuln as unknown as { database_specific?: { severity?: string } }).database_specific;
  const label = ds?.severity?.toUpperCase();
  if (!label) return null;
  const sev = OSV_DB_SEVERITY[label];
  if (!sev) return null;
  switch (sev) {
    case 'CRITICAL': return 9.5;
    case 'HIGH': return 7.5;
    case 'MEDIUM': return 5.5;
    case 'LOW': return 2.5;
    default: return null;
  }
}

export function maxSeverity(severities: Severity[]): Severity {
  let max: Severity = 'NONE';
  for (const s of severities) {
    if (SEVERITY_RANK[s] > SEVERITY_RANK[max]) max = s;
  }
  return max;
}

export function compareSeverity(a: Severity | null, b: Severity | null): number {
  return SEVERITY_RANK[b ?? 'NONE'] - SEVERITY_RANK[a ?? 'NONE'];
}

export function summarizeVuln(vuln: OsvVuln): {
  severity: Severity;
  cvssScore: number | null;
  cvssVector: string | null;
  fixedVersions: string[];
} {
  const { score, vector } = extractCvssScore(vuln);
  const severity = bucketByCvss(score);
  const fixedVersions: string[] = [];
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const e of range.events) {
        if (e.fixed) fixedVersions.push(e.fixed);
      }
    }
  }
  return { severity, cvssScore: score, cvssVector: vector, fixedVersions: Array.from(new Set(fixedVersions)) };
}
