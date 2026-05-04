import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { isUnauthorized, requireUser } from '@/lib/auth';
import { buildCycloneDxVex, buildHtmlReport, buildJsonReport } from '@/lib/report-builder';

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string; format: string }> },
) {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;
  const { id, format } = await params;

  const analysis = await prisma.analysis.findFirst({
    where: { id, ownerId: auth.id },
    include: { components: { include: { vulnerabilities: true } } },
  });
  if (!analysis) return NextResponse.json({ error: 'not found' }, { status: 404 });

  const baseName = analysis.filename.replace(/\.[^.]+$/, '');

  switch (format.toLowerCase()) {
    case 'json': {
      const body = JSON.stringify(buildJsonReport(analysis), null, 2);
      return new Response(body, {
        headers: {
          'content-type': 'application/json',
          'content-disposition': `attachment; filename="${baseName}-report.json"`,
        },
      });
    }
    case 'vex':
    case 'cyclonedx-vex': {
      const body = JSON.stringify(buildCycloneDxVex(analysis), null, 2);
      return new Response(body, {
        headers: {
          'content-type': 'application/vnd.cyclonedx+json',
          'content-disposition': `attachment; filename="${baseName}-vex.json"`,
        },
      });
    }
    case 'html':
    case 'pdf': {
      const body = buildHtmlReport(analysis);
      return new Response(body, {
        headers: { 'content-type': 'text/html; charset=utf-8' },
      });
    }
    default:
      return NextResponse.json({ error: 'unknown format' }, { status: 400 });
  }
}
