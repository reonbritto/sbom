import { getJson, setJson } from './redis';

const EPSS_BASE = 'https://api.first.org/data/v1/epss';
const BATCH_SIZE = 80;
const TTL = 86_400;

export interface EpssScore {
  cve: string;
  epss: number;
  percentile: number;
  date: string;
}

interface EpssResponse {
  data: { cve: string; epss: string; percentile: string; date: string }[];
}

export async function getEpssBatch(cveIds: string[]): Promise<Map<string, EpssScore>> {
  const out = new Map<string, EpssScore>();
  const uniq = Array.from(new Set(cveIds.filter((id) => /^CVE-\d{4}-\d+$/i.test(id))));
  if (uniq.length === 0) return out;

  const misses: string[] = [];
  for (const id of uniq) {
    const cached = await getJson<EpssScore>(`epss:${id}`);
    if (cached) out.set(id, cached);
    else misses.push(id);
  }

  for (let i = 0; i < misses.length; i += BATCH_SIZE) {
    const chunk = misses.slice(i, i + BATCH_SIZE);
    try {
      const url = `${EPSS_BASE}?cve=${chunk.join(',')}`;
      const res = await fetch(url, { headers: { accept: 'application/json' } });
      if (!res.ok) continue;
      const json = (await res.json()) as EpssResponse;
      for (const row of json.data ?? []) {
        const score: EpssScore = {
          cve: row.cve,
          epss: parseFloat(row.epss),
          percentile: parseFloat(row.percentile),
          date: row.date,
        };
        out.set(row.cve, score);
        await setJson(`epss:${row.cve}`, score, TTL);
      }
    } catch (err) {
      console.error('[epss] fetch failed:', (err as Error).message);
    }
  }
  return out;
}

export async function getEpssOne(cve: string): Promise<EpssScore | null> {
  const map = await getEpssBatch([cve]);
  return map.get(cve) ?? null;
}

export function epssPriority(score: EpssScore | null | undefined): 'urgent' | 'elevated' | 'low' | null {
  if (!score) return null;
  if (score.percentile >= 0.95) return 'urgent';
  if (score.percentile >= 0.5) return 'elevated';
  return 'low';
}

export function extractCveIds(aliases: string[] | undefined, primaryId: string): string[] {
  const ids = new Set<string>();
  if (/^CVE-/i.test(primaryId)) ids.add(primaryId.toUpperCase());
  for (const a of aliases ?? []) {
    if (/^CVE-/i.test(a)) ids.add(a.toUpperCase());
  }
  return Array.from(ids);
}
