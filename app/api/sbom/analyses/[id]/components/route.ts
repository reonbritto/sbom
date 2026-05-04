import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { isUnauthorized, requireUser } from '@/lib/auth';
import { compareSeverity } from '@/lib/analytics';
import type { Severity } from '@/lib/types';

const SORTABLE = new Set(['name', 'version', 'ecosystem', 'vulnCount', 'maxSeverity']);

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;
  const { id } = await params;

  const analysis = await prisma.analysis.findFirst({
    where: { id, ownerId: auth.id },
    select: { id: true },
  });
  if (!analysis) return NextResponse.json({ error: 'not found' }, { status: 404 });

  const search = req.nextUrl.searchParams.get('search')?.toLowerCase() ?? '';
  const severityFilter = req.nextUrl.searchParams.get('severity') ?? '';
  const sort = req.nextUrl.searchParams.get('sort') ?? 'maxSeverity';
  const order = req.nextUrl.searchParams.get('order') === 'asc' ? 'asc' : 'desc';

  let components = await prisma.component.findMany({
    where: { analysisId: id },
    select: {
      id: true,
      purl: true,
      name: true,
      version: true,
      ecosystem: true,
      licenses: true,
      vulnCount: true,
      maxSeverity: true,
    },
  });

  if (search) {
    components = components.filter(
      (c) => c.name.toLowerCase().includes(search) || c.purl.toLowerCase().includes(search),
    );
  }
  if (severityFilter) {
    components = components.filter((c) => c.maxSeverity === severityFilter);
  }

  if (SORTABLE.has(sort)) {
    components.sort((a, b) => {
      if (sort === 'maxSeverity') {
        const cmp = compareSeverity(a.maxSeverity as Severity | null, b.maxSeverity as Severity | null);
        return order === 'asc' ? -cmp : cmp;
      }
      const av = (a as unknown as Record<string, unknown>)[sort];
      const bv = (b as unknown as Record<string, unknown>)[sort];
      if (av === bv) return 0;
      if (av === null || av === undefined) return 1;
      if (bv === null || bv === undefined) return -1;
      const cmp = av < bv ? -1 : 1;
      return order === 'asc' ? cmp : -cmp;
    });
  }

  return NextResponse.json({ components });
}
