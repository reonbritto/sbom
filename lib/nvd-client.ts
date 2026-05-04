import { getJson, setJson } from './redis';
import { extractCveIds } from './epss-client';
import type { OsvVuln } from './types';

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const TTL = 86_400 * 7;

export interface NvdEnrichment {
  cveId: string;
  description: string | null;
  published: string | null;
  lastModified: string | null;
  vulnStatus: string | null;
  cvssV3Score: number | null;
  cvssV3Severity: string | null;
  cvssV3Vector: string | null;
  cvssV2Score: number | null;
  cvssV2Vector: string | null;
  cweIds: string[];
  cweNames: Record<string, string>;
  knownExploited: boolean;
  knownExploitedDate?: string | null;
  knownExploitedDueDate?: string | null;
  knownExploitedRequiredAction?: string | null;
  knownExploitedVulnName?: string | null;
  ransomwareCampaignUse?: string | null;
  references: { url: string; tags: string[] }[];
  vendors: string[];
  cpes: string[];
}

interface NvdResponse {
  vulnerabilities?: { cve?: NvdCve }[];
}

interface NvdCve {
  id: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: {
    cvssMetricV31?: { cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }[];
    cvssMetricV30?: { cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }[];
    cvssMetricV2?: { cvssData: { baseScore: number; vectorString: string } }[];
  };
  cisaExploitAdd?: string;
  cisaActionDue?: string;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;
  weaknesses?: { description: { lang: string; value: string }[] }[];
  references?: { url: string; tags?: string[] }[];
  configurations?: { nodes: { cpeMatch?: { criteria: string }[] }[] }[];
}

export async function enrichWithNvd(vuln: OsvVuln): Promise<NvdEnrichment | null> {
  const cveIds = extractCveIds(vuln.aliases, vuln.id);
  if (cveIds.length === 0) return null;
  return enrichByCveId(cveIds[0]);
}

export async function enrichByCveId(cveIdInput: string): Promise<NvdEnrichment | null> {
  const primaryCve = cveIdInput.toUpperCase();
  if (!/^CVE-\d{4}-\d+$/.test(primaryCve)) return null;
  const cacheKey = `nvd:v2:${primaryCve}`;
  const cached = await getJson<NvdEnrichment>(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetch(`${NVD_BASE}?cveId=${encodeURIComponent(primaryCve)}`, {
      headers: { accept: 'application/json' },
    });
    if (!res.ok) {
      if (res.status === 404 || res.status === 429) return null;
      throw new Error(`HTTP ${res.status}`);
    }
    const json = (await res.json()) as NvdResponse;
    const cve = json.vulnerabilities?.[0]?.cve;
    if (!cve) return null;

    const cweIds: string[] = [];
    const cweNames: Record<string, string> = {};
    for (const w of cve.weaknesses ?? []) {
      for (const d of w.description) {
        if (d.lang === 'en' && /^CWE-/.test(d.value)) {
          cweIds.push(d.value);
        }
      }
    }

    const cpes = new Set<string>();
    for (const conf of cve.configurations ?? []) {
      for (const node of conf.nodes ?? []) {
        for (const m of node.cpeMatch ?? []) cpes.add(m.criteria);
      }
    }

    const vendors = new Set<string>();
    for (const cpe of cpes) {
      const parts = cpe.split(':');
      if (parts.length > 4 && parts[3]) vendors.add(parts[3]);
    }

    const description = cve.descriptions?.find((d) => d.lang === 'en')?.value ?? null;
    const v31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const v30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const v2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
    const v3 = v31 ?? v30;

    const enrichment: NvdEnrichment = {
      cveId: primaryCve,
      description,
      published: cve.published ?? null,
      lastModified: cve.lastModified ?? null,
      vulnStatus: cve.vulnStatus ?? null,
      cvssV3Score: v3?.baseScore ?? null,
      cvssV3Severity: v3?.baseSeverity ?? null,
      cvssV3Vector: v3?.vectorString ?? null,
      cvssV2Score: v2?.baseScore ?? null,
      cvssV2Vector: v2?.vectorString ?? null,
      cweIds: Array.from(new Set(cweIds)),
      cweNames,
      knownExploited: !!cve.cisaExploitAdd,
      knownExploitedDate: cve.cisaExploitAdd ?? null,
      knownExploitedDueDate: cve.cisaActionDue ?? null,
      knownExploitedRequiredAction: cve.cisaRequiredAction ?? null,
      knownExploitedVulnName: cve.cisaVulnerabilityName ?? null,
      ransomwareCampaignUse: null,
      references: (cve.references ?? []).map((r) => ({ url: r.url, tags: r.tags ?? [] })),
      vendors: Array.from(vendors),
      cpes: Array.from(cpes).slice(0, 50),
    };
    await setJson(cacheKey, enrichment, TTL);
    return enrichment;
  } catch (err) {
    console.error(`[nvd] ${primaryCve}:`, (err as Error).message);
    return null;
  }
}

export interface CweInfo {
  id: string;
  name: string;
  description: string;
  url: string;
}

const CWE_CACHE_TTL = 86_400 * 30;

export async function getCweInfo(cweId: string): Promise<CweInfo | null> {
  const id = cweId.replace(/^CWE-/i, '');
  if (!/^\d+$/.test(id)) return null;
  const cacheKey = `cwe:${id}`;
  const cached = await getJson<CweInfo>(cacheKey);
  if (cached) return cached;

  const fallback = CWE_CATALOG[id];
  if (fallback) {
    const info: CweInfo = {
      id: `CWE-${id}`,
      name: fallback.name,
      description: fallback.description,
      url: `https://cwe.mitre.org/data/definitions/${id}.html`,
    };
    await setJson(cacheKey, info, CWE_CACHE_TTL);
    return info;
  }
  const info: CweInfo = {
    id: `CWE-${id}`,
    name: `Weakness ${id}`,
    description: '',
    url: `https://cwe.mitre.org/data/definitions/${id}.html`,
  };
  return info;
}

const CWE_CATALOG: Record<string, { name: string; description: string }> = {
  '20': { name: 'Improper Input Validation', description: 'The product does not validate or incorrectly validates input.' },
  '22': { name: 'Path Traversal', description: 'The product uses external input without sanitizing path elements.' },
  '78': { name: 'OS Command Injection', description: 'Improper neutralization of special elements used in an OS command.' },
  '79': { name: 'Cross-site Scripting (XSS)', description: 'Improper neutralization of input during web page generation.' },
  '89': { name: 'SQL Injection', description: 'Improper neutralization of special elements used in an SQL command.' },
  '94': { name: 'Code Injection', description: 'The product constructs all or part of a code segment using externally-influenced input.' },
  '119': { name: 'Memory Buffer Errors', description: 'Operations on a memory buffer outside its bounds.' },
  '120': { name: 'Buffer Copy without Checking Size of Input', description: 'Classic buffer overflow.' },
  '125': { name: 'Out-of-bounds Read', description: 'The product reads data past the end, or before the beginning, of the intended buffer.' },
  '190': { name: 'Integer Overflow or Wraparound', description: 'A calculation can produce a value outside the integer range.' },
  '200': { name: 'Information Exposure', description: 'The product exposes sensitive information to an unauthorized actor.' },
  '209': { name: 'Information Exposure Through an Error Message', description: 'Sensitive info revealed in error messages.' },
  '250': { name: 'Execution with Unnecessary Privileges', description: 'The product runs at a higher privilege level than required.' },
  '269': { name: 'Improper Privilege Management', description: 'Privileges are not properly assigned, modified, tracked, or checked.' },
  '276': { name: 'Incorrect Default Permissions', description: 'Files are installed with incorrectly permissive defaults.' },
  '287': { name: 'Improper Authentication', description: 'When an actor claims an identity, the product does not properly verify it.' },
  '290': { name: 'Authentication Bypass by Spoofing', description: 'Authentication is bypassed using a spoofed identity.' },
  '294': { name: 'Authentication Bypass by Capture-replay', description: 'Captured request can be replayed to bypass authentication.' },
  '295': { name: 'Improper Certificate Validation', description: 'The product does not validate, or incorrectly validates, a certificate.' },
  '306': { name: 'Missing Authentication', description: 'The product does not perform authentication for critical functionality.' },
  '352': { name: 'Cross-Site Request Forgery (CSRF)', description: 'The product does not verify whether a request was intentionally provided.' },
  '400': { name: 'Uncontrolled Resource Consumption', description: 'The product does not properly limit resource allocation (DoS).' },
  '416': { name: 'Use After Free', description: 'Referencing memory after it has been freed.' },
  '434': { name: 'Unrestricted File Upload', description: 'The product allows upload of dangerous file types.' },
  '476': { name: 'NULL Pointer Dereference', description: 'A NULL pointer dereference occurs.' },
  '502': { name: 'Deserialization of Untrusted Data', description: 'Deserialization of data without sufficient verification.' },
  '521': { name: 'Weak Password Requirements', description: 'Password requirements are too weak.' },
  '522': { name: 'Insufficiently Protected Credentials', description: 'Credentials are not protected adequately.' },
  '601': { name: 'Open Redirect', description: 'A web app accepts user input that specifies a link to an external site.' },
  '611': { name: 'XML External Entity (XXE)', description: 'XML processing of external entity references.' },
  '662': { name: 'Improper Synchronization', description: 'Race condition or synchronization issue.' },
  '732': { name: 'Incorrect Permission Assignment', description: 'A critical resource is assigned incorrect permissions.' },
  '770': { name: 'Allocation Without Limits or Throttling', description: 'Resource allocated without a hard cap.' },
  '787': { name: 'Out-of-bounds Write', description: 'Writing data past the end, or before the beginning, of the intended buffer.' },
  '798': { name: 'Use of Hard-coded Credentials', description: 'Hard-coded password or secret in source.' },
  '862': { name: 'Missing Authorization', description: 'The product does not perform an authorization check.' },
  '863': { name: 'Incorrect Authorization', description: 'Authorization decisions are made incorrectly.' },
  '915': { name: 'Improperly Controlled Modification of Object Attributes', description: 'Prototype pollution and similar.' },
  '917': { name: 'Expression Language Injection', description: 'Improper neutralization of EL statements.' },
  '918': { name: 'Server-Side Request Forgery (SSRF)', description: 'Server fetches a URL controlled by the attacker.' },
  '1188': { name: 'Insecure Default Initialization', description: 'Resource initialized with insecure default value.' },
  '1321': { name: 'Prototype Pollution', description: 'JS object prototype modification via attacker-controlled input.' },
  '1333': { name: 'Inefficient Regex (ReDoS)', description: 'Regex with worst-case exponential complexity.' },
};
