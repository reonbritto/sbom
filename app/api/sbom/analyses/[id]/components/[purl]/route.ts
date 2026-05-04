import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { isUnauthorized, requireUser } from '@/lib/auth';
import { getJson } from '@/lib/redis';
import type { OsvVuln } from '@/lib/types';
import { summarizeVuln } from '@/lib/analytics';

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string; purl: string }> },
) {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;
  const { id, purl: purlEncoded } = await params;
  const purl = decodeBase64Url(purlEncoded);

  const analysis = await prisma.analysis.findFirst({
    where: { id, ownerId: auth.id },
    select: { id: true },
  });
  if (!analysis) return NextResponse.json({ error: 'not found' }, { status: 404 });

  const component = await prisma.component.findFirst({
    where: { analysisId: id, purl },
    include: { vulnerabilities: true },
  });
  if (!component) return NextResponse.json({ error: 'not found' }, { status: 404 });

  const vulns = await Promise.all(
    component.vulnerabilities.map(async (cv) => {
      const v = await getJson<OsvVuln>(`vuln:${cv.vulnId}`);
      const summary = v ? summarizeVuln(v) : { severity: cv.severity, cvssScore: cv.cvssScore, cvssVector: null, fixedVersions: [] };
      return {
        id: cv.vulnId,
        severity: cv.severity,
        cvssScore: cv.cvssScore,
        summary: v?.summary ?? null,
        aliases: v?.aliases ?? [],
        fixedVersions: summary.fixedVersions,
      };
    }),
  );

  return NextResponse.json({
    component: {
      id: component.id,
      purl: component.purl,
      name: component.name,
      version: component.version,
      ecosystem: component.ecosystem,
      licenses: component.licenses,
      vulnCount: component.vulnCount,
      maxSeverity: component.maxSeverity,
    },
    vulnerabilities: vulns,
  });
}

function decodeBase64Url(s: string): string {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
}
