import { getJson, redis, setJson } from './redis';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const TTL = 86_400;
const CACHE_KEY = 'kev:catalog:v1';
const META_KEY = 'kev:catalog:meta';

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
}

interface KevCatalog {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

interface KevMeta {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  refreshedAt: string;
}

let inflight: Promise<Map<string, KevEntry>> | null = null;

export async function refreshKevCatalog(force = false): Promise<KevMeta | null> {
  if (!force) {
    const meta = await getJson<KevMeta>(META_KEY);
    if (meta) {
      const ageMs = Date.now() - new Date(meta.refreshedAt).getTime();
      if (ageMs < TTL * 1000) return meta;
    }
  }

  try {
    const res = await fetch(KEV_URL, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = (await res.json()) as KevCatalog;
    const meta: KevMeta = {
      catalogVersion: json.catalogVersion,
      dateReleased: json.dateReleased,
      count: json.vulnerabilities?.length ?? 0,
      refreshedAt: new Date().toISOString(),
    };
    await setJson(CACHE_KEY, json.vulnerabilities, TTL);
    await setJson(META_KEY, meta, TTL);
    inflight = null;
    return meta;
  } catch (err) {
    console.error('[kev] catalog refresh failed:', (err as Error).message);
    return null;
  }
}

async function loadIndex(): Promise<Map<string, KevEntry>> {
  if (inflight) return inflight;
  inflight = (async () => {
    const cached = await getJson<KevEntry[]>(CACHE_KEY);
    let entries = cached;
    if (!entries) {
      await refreshKevCatalog(true);
      entries = (await getJson<KevEntry[]>(CACHE_KEY)) ?? [];
    }
    const map = new Map<string, KevEntry>();
    for (const e of entries) map.set(e.cveID.toUpperCase(), e);
    return map;
  })();
  return inflight;
}

export async function lookupKev(cveId: string): Promise<KevEntry | null> {
  const idx = await loadIndex();
  return idx.get(cveId.toUpperCase()) ?? null;
}

export async function lookupKevBatch(cveIds: string[]): Promise<Map<string, KevEntry>> {
  const idx = await loadIndex();
  const out = new Map<string, KevEntry>();
  for (const id of cveIds) {
    const hit = idx.get(id.toUpperCase());
    if (hit) out.set(id.toUpperCase(), hit);
  }
  return out;
}

export async function getKevMeta(): Promise<KevMeta | null> {
  return getJson<KevMeta>(META_KEY);
}

export function invalidateKevCache(): Promise<unknown> {
  inflight = null;
  return Promise.all([redis.del(CACHE_KEY), redis.del(META_KEY)]);
}
