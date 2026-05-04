import pLimit from 'p-limit';
import { getJson, setJson } from './redis';

const BASE = 'https://api.deps.dev/v3';
const TTL = 86_400;
const CONCURRENCY = 10;
const limit = pLimit(CONCURRENCY);

const ECOSYSTEM_TO_DEPSDEV: Record<string, string> = {
  PyPI: 'pypi',
  npm: 'npm',
  Maven: 'maven',
  Go: 'go',
  RubyGems: 'rubygems',
  NuGet: 'nuget',
  'crates.io': 'cargo',
  Packagist: 'packagist',
};

export interface PackageReputation {
  ecosystem: string | null;
  name: string;
  found: boolean;
  dependentCount: number | null;
  downloadCount: number | null;
  openssfScorecard: number | null;
  scorecardChecks: { name: string; score: number }[];
  isMalicious: boolean;
  versionsCount: number | null;
  firstPublished: string | null;
  lastPublished: string | null;
  links: { type: string; url: string }[];
}

interface DepsDevPackage {
  packageKey?: { system?: string; name?: string };
  versions?: { versionKey?: { version?: string }; publishedAt?: string }[];
}

interface DepsDevVersion {
  versionKey?: { system?: string; name?: string; version?: string };
  publishedAt?: string;
  isDefault?: boolean;
  licenses?: string[];
  advisoryKeys?: { id: string }[];
  links?: { label: string; url: string }[];
  projects?: { projectKey?: { id?: string }; scorecardV2?: ScorecardV2 }[];
  relatedProjects?: { projectKey?: { id?: string } }[];
  registries?: string[];
  attestations?: unknown[];
}

interface ScorecardV2 {
  overallScore?: number;
  checks?: { name: string; score: number; reason?: string }[];
}

export async function getReputation(
  ecosystem: string | null,
  name: string,
  version: string,
): Promise<PackageReputation | null> {
  const sys = ecosystem ? ECOSYSTEM_TO_DEPSDEV[ecosystem] : null;
  if (!sys) return null;

  const cacheKey = `depsdev:${sys}:${name.toLowerCase()}:${version}`;
  const cached = await getJson<PackageReputation>(cacheKey);
  if (cached) return cached;

  return limit(async () => {
    try {
      const [pkg, ver] = await Promise.all([
        fetchJson<DepsDevPackage>(`${BASE}/systems/${sys}/packages/${encodeURIComponent(name)}`),
        fetchJson<DepsDevVersion>(
          `${BASE}/systems/${sys}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
        ),
      ]);

      const found = pkg !== null || ver !== null;
      const versions = pkg?.versions ?? [];
      const sortedByDate = versions
        .filter((v) => v.publishedAt)
        .sort((a, b) => (a.publishedAt! > b.publishedAt! ? 1 : -1));

      const project = ver?.projects?.[0];
      const scorecard = project?.scorecardV2;
      const overall = scorecard?.overallScore ?? null;
      const checks =
        scorecard?.checks?.map((c) => ({ name: c.name, score: c.score })) ?? [];

      const reputation: PackageReputation = {
        ecosystem,
        name,
        found,
        dependentCount: null,
        downloadCount: null,
        openssfScorecard: overall,
        scorecardChecks: checks,
        isMalicious: (ver?.advisoryKeys ?? []).some((a) => /^MAL-/i.test(a.id)),
        versionsCount: versions.length || null,
        firstPublished: sortedByDate[0]?.publishedAt ?? null,
        lastPublished: sortedByDate[sortedByDate.length - 1]?.publishedAt ?? null,
        links: (ver?.links ?? []).map((l) => ({ type: l.label, url: l.url })),
      };
      await setJson(cacheKey, reputation, TTL);
      return reputation;
    } catch (err) {
      console.error(`[depsdev] ${sys}/${name}@${version}:`, (err as Error).message);
      return null;
    }
  });
}

async function fetchJson<T>(url: string): Promise<T | null> {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as T;
}

export function isWellEstablished(rep: PackageReputation | null): boolean {
  if (!rep || !rep.found) return false;
  if ((rep.versionsCount ?? 0) >= 3) return true;
  if (rep.firstPublished) {
    const ageMs = Date.now() - new Date(rep.firstPublished).getTime();
    if (ageMs > 1000 * 60 * 60 * 24 * 365) return true;
  }
  return false;
}
