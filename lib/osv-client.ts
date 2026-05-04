import pLimit from 'p-limit';
import { osvPackageName, parsePurl } from './purl-mapper';
import { getJson, setJson } from './redis';
import type { OsvBatchResult, OsvVuln, OsvVulnRef, ParsedComponent } from './types';

const OSV_BASE = 'https://api.osv.dev';
const BATCH_SIZE = 1000;
const VULN_TTL = parseInt(process.env.VULN_CACHE_TTL_SECONDS ?? '86400', 10);
const PURL_TTL = parseInt(process.env.CACHE_TTL_SECONDS ?? '3600', 10);
const CONCURRENCY = parseInt(process.env.OSV_CONCURRENCY ?? '10', 10);

interface ScanResult {
  byPurl: Map<string, OsvVulnRef[]>;
  vulns: Map<string, OsvVuln>;
}

export async function scanComponents(components: ParsedComponent[]): Promise<ScanResult> {
  const queryable = components.filter((c) => c.ecosystem && c.version);

  const byPurl = new Map<string, OsvVulnRef[]>();
  const cacheMisses: ParsedComponent[] = [];
  for (const c of queryable) {
    const cached = await getJson<OsvVulnRef[]>(`purl:${c.purl}`);
    if (cached) {
      byPurl.set(c.purl, cached);
    } else {
      cacheMisses.push(c);
    }
  }

  for (let i = 0; i < cacheMisses.length; i += BATCH_SIZE) {
    const chunk = cacheMisses.slice(i, i + BATCH_SIZE);
    const queries = chunk.map((c) => {
      const parsed = parsePurl(c.purl)!;
      return {
        package: { name: osvPackageName(parsed), ecosystem: c.ecosystem! },
        version: c.version,
      };
    });
    const result = await postWithRetry<OsvBatchResult>(`${OSV_BASE}/v1/querybatch`, { queries });
    for (let j = 0; j < chunk.length; j++) {
      const refs = result.results[j]?.vulns ?? [];
      byPurl.set(chunk[j].purl, refs);
      await setJson(`purl:${chunk[j].purl}`, refs, PURL_TTL);
    }
  }

  const allIds = new Set<string>();
  for (const refs of byPurl.values()) for (const r of refs) allIds.add(r.id);

  const vulns = new Map<string, OsvVuln>();
  const limit = pLimit(CONCURRENCY);
  await Promise.all(
    Array.from(allIds).map((id) =>
      limit(async () => {
        const cached = await getJson<OsvVuln>(`vuln:${id}`);
        if (cached) {
          vulns.set(id, cached);
          return;
        }
        try {
          const v = await postWithRetry<OsvVuln>(`${OSV_BASE}/v1/vulns/${encodeURIComponent(id)}`, undefined, 'GET');
          vulns.set(id, v);
          await setJson(`vuln:${id}`, v, VULN_TTL);
        } catch (err) {
          console.error(`Failed to fetch vuln ${id}:`, (err as Error).message);
        }
      }),
    ),
  );

  return { byPurl, vulns };
}

export async function getVuln(id: string): Promise<OsvVuln | null> {
  const cached = await getJson<OsvVuln>(`vuln:${id}`);
  if (cached) return cached;
  try {
    const v = await postWithRetry<OsvVuln>(`${OSV_BASE}/v1/vulns/${encodeURIComponent(id)}`, undefined, 'GET');
    await setJson(`vuln:${id}`, v, VULN_TTL);
    return v;
  } catch {
    return null;
  }
}

async function postWithRetry<T>(url: string, body?: unknown, method: 'GET' | 'POST' = 'POST'): Promise<T> {
  const maxRetries = 3;
  let lastErr: unknown;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const res = await fetch(url, {
        method,
        headers: body ? { 'content-type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      if (res.status === 429 || res.status >= 500) {
        throw new Error(`HTTP ${res.status}`);
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      return (await res.json()) as T;
    } catch (err) {
      lastErr = err;
      if (attempt < maxRetries - 1) {
        await new Promise((r) => setTimeout(r, 500 * Math.pow(2, attempt)));
      }
    }
  }
  throw lastErr;
}
