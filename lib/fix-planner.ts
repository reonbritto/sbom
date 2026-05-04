import type { OsvVuln } from './types';

export interface FixPlan {
  recommendedVersion: string | null;
  fixesVulnIds: string[];
  unfixableVulnIds: string[];
  alternativeVersions: string[];
}

export function planFix(currentVersion: string, vulns: OsvVuln[]): FixPlan {
  const allFixed: { vulnId: string; fixed: string[] }[] = [];
  const unfixable: string[] = [];

  for (const v of vulns) {
    const fixed = collectFixedVersions(v);
    if (fixed.length === 0) unfixable.push(v.id);
    else allFixed.push({ vulnId: v.id, fixed });
  }

  if (allFixed.length === 0) {
    return { recommendedVersion: null, fixesVulnIds: [], unfixableVulnIds: unfixable, alternativeVersions: [] };
  }

  const candidates = new Set<string>();
  for (const f of allFixed) for (const v of f.fixed) candidates.add(v);

  let best: { version: string; fixes: string[]; rank: number } | null = null;
  for (const candidate of candidates) {
    const fixes: string[] = [];
    for (const f of allFixed) {
      if (f.fixed.some((fx) => versionGteOrEqual(candidate, fx))) {
        fixes.push(f.vulnId);
      }
    }
    const rank = fixes.length * 1000 - rankPenalty(candidate, currentVersion);
    if (!best || rank > best.rank) {
      best = { version: candidate, fixes, rank };
    }
  }

  return {
    recommendedVersion: best?.version ?? null,
    fixesVulnIds: best?.fixes ?? [],
    unfixableVulnIds: unfixable,
    alternativeVersions: Array.from(candidates).filter((v) => v !== best?.version).slice(0, 5),
  };
}

function collectFixedVersions(v: OsvVuln): string[] {
  const out: string[] = [];
  for (const aff of v.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const e of range.events) {
        if (e.fixed) out.push(e.fixed);
      }
    }
  }
  return Array.from(new Set(out));
}

function versionGteOrEqual(a: string, b: string): boolean {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return a === b;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const av = pa[i] ?? 0;
    const bv = pb[i] ?? 0;
    if (av > bv) return true;
    if (av < bv) return false;
  }
  return true;
}

function parseVersion(v: string): number[] | null {
  const m = v.match(/^v?(\d+(?:\.\d+)*)/);
  if (!m) return null;
  return m[1].split('.').map((n) => parseInt(n, 10));
}

function rankPenalty(candidate: string, current: string): number {
  const c = parseVersion(candidate);
  const cur = parseVersion(current);
  if (!c || !cur) return 0;
  const majorJump = Math.abs((c[0] ?? 0) - (cur[0] ?? 0));
  return majorJump * 5;
}
