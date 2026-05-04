import type { PackageReputation } from './depsdev-client';
import type { Severity } from './types';

export interface RiskInputs {
  maxCvss: number | null;
  maxEpss: number | null;
  isMalicious: boolean;
  hasKev?: boolean;
  reputation: PackageReputation | null;
  vulnCount: number;
}

export interface RiskScore {
  score: number;
  band: 'critical' | 'high' | 'moderate' | 'low' | 'none';
  rationale: string[];
}

export function computeRiskScore(inputs: RiskInputs): RiskScore {
  const rationale: string[] = [];
  let score = 0;

  if (inputs.isMalicious) {
    rationale.push('Malicious package (highest priority).');
    return { score: 100, band: 'critical', rationale };
  }

  if (inputs.hasKev) {
    rationale.push('CISA Known Exploited Vulnerability (KEV) — actively exploited in the wild → +25');
    score += 25;
  }

  if (inputs.maxCvss !== null) {
    const cvssContrib = Math.min(50, (inputs.maxCvss / 10) * 50);
    score += cvssContrib;
    rationale.push(`CVSS ${inputs.maxCvss.toFixed(1)} → +${cvssContrib.toFixed(0)}`);
  }

  if (inputs.maxEpss !== null) {
    const epssContrib = Math.min(35, inputs.maxEpss * 35);
    score += epssContrib;
    if (epssContrib >= 20) {
      rationale.push(`EPSS ${(inputs.maxEpss * 100).toFixed(1)}% (active exploitation likely) → +${epssContrib.toFixed(0)}`);
    } else if (epssContrib > 0) {
      rationale.push(`EPSS ${(inputs.maxEpss * 100).toFixed(2)}% → +${epssContrib.toFixed(0)}`);
    }
  }

  if (inputs.vulnCount > 1) {
    const stack = Math.min(10, Math.log2(inputs.vulnCount) * 4);
    score += stack;
    rationale.push(`${inputs.vulnCount} vulnerabilities stacked → +${stack.toFixed(0)}`);
  }

  if (inputs.reputation) {
    const rep = inputs.reputation;
    if (rep.openssfScorecard !== null) {
      if (rep.openssfScorecard < 3) {
        score += 5;
        rationale.push(`Low OpenSSF Scorecard (${rep.openssfScorecard.toFixed(1)}) → +5`);
      } else if (rep.openssfScorecard >= 7) {
        score -= 5;
        rationale.push(`High OpenSSF Scorecard (${rep.openssfScorecard.toFixed(1)}) → -5`);
      }
    }
    if ((rep.versionsCount ?? 0) <= 1) {
      score += 5;
      rationale.push('Single-release package → +5');
    }
  }

  score = Math.max(0, Math.min(100, score));
  let band: RiskScore['band'] = 'none';
  if (score >= 80) band = 'critical';
  else if (score >= 60) band = 'high';
  else if (score >= 35) band = 'moderate';
  else if (score >= 10) band = 'low';

  return { score: Math.round(score), band, rationale };
}

export function bandToSeverity(band: RiskScore['band']): Severity {
  switch (band) {
    case 'critical': return 'CRITICAL';
    case 'high': return 'HIGH';
    case 'moderate': return 'MEDIUM';
    case 'low': return 'LOW';
    case 'none': return 'NONE';
  }
}
