import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { isUnauthorized, requireUser } from '@/lib/auth';
import { emptyDistribution } from '@/lib/analytics';
import type { Severity } from '@/lib/types';

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;
  const { id } = await params;

  const analysis = await prisma.analysis.findFirst({
    where: { id, ownerId: auth.id },
    select: { id: true, componentCount: true, vulnerableCount: true },
  });
  if (!analysis) return NextResponse.json({ error: 'not found' }, { status: 404 });

  const components = await prisma.component.findMany({
    where: { analysisId: id },
    select: { name: true, version: true, purl: true, vulnCount: true, maxSeverity: true, licenses: true },
  });

  const distribution = emptyDistribution();
  const licenseCounts: Record<string, number> = {};

  for (const c of components) {
    const sev = (c.maxSeverity ?? 'NONE') as Severity;
    distribution[sev] = (distribution[sev] ?? 0) + 1;
    const licenses = Array.isArray(c.licenses) ? (c.licenses as string[]) : [];
    for (const l of licenses) {
      licenseCounts[l] = (licenseCounts[l] ?? 0) + 1;
    }
  }

  const topVulnerable = components
    .filter((c) => c.vulnCount > 0)
    .sort((a, b) => b.vulnCount - a.vulnCount)
    .slice(0, 10)
    .map((c) => ({ name: c.name, version: c.version, purl: c.purl, vulnCount: c.vulnCount, maxSeverity: c.maxSeverity }));

  return NextResponse.json({
    componentCount: analysis.componentCount,
    vulnerableCount: analysis.vulnerableCount,
    severityDistribution: distribution,
    licenseCounts,
    topVulnerable,
  });
}
