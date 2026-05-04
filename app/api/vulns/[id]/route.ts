import { NextRequest, NextResponse } from 'next/server';
import { isUnauthorized, requireUser } from '@/lib/auth';
import { getVuln } from '@/lib/osv-client';
import { summarizeVuln } from '@/lib/analytics';
import { extractCveIds, getEpssBatch, epssPriority } from '@/lib/epss-client';
import { isOsvMaliciousId } from '@/lib/malicious-detector';

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;
  const { id } = await params;

  const vuln = await getVuln(id);
  if (!vuln) return NextResponse.json({ error: 'not found' }, { status: 404 });

  const summary = summarizeVuln(vuln);
  const cveIds = extractCveIds(vuln.aliases, vuln.id);
  const epssMap = await getEpssBatch(cveIds);

  let bestEpss = null as null | { cve: string; epss: number; percentile: number; date: string };
  for (const cve of cveIds) {
    const e = epssMap.get(cve);
    if (e && (bestEpss === null || e.epss > bestEpss.epss)) bestEpss = e;
  }

  return NextResponse.json({
    id: vuln.id,
    aliases: vuln.aliases ?? [],
    summary: vuln.summary ?? '',
    details: vuln.details ?? '',
    severity: summary.severity,
    cvssScore: summary.cvssScore,
    cvssVector: summary.cvssVector,
    fixedVersions: summary.fixedVersions,
    references: vuln.references ?? [],
    published: vuln.published ?? null,
    modified: vuln.modified ?? null,
    affected: vuln.affected ?? [],
    epss: bestEpss,
    epssPriority: epssPriority(bestEpss),
    isMalicious: isOsvMaliciousId(vuln.id),
  });
}
