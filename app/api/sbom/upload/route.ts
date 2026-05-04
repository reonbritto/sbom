import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { parseSbom, SbomParseError } from '@/lib/sbom-parser';
import { isUnauthorized, requireUser } from '@/lib/auth';
import { runScan } from '@/lib/scan';
import { sbomUploads } from '@/lib/metrics';

export async function POST(req: NextRequest) {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;

  const form = await req.formData().catch(() => null);
  const file = form?.get('file');
  if (!(file instanceof File)) {
    return NextResponse.json({ error: 'missing file field' }, { status: 400 });
  }
  const buf = Buffer.from(await file.arrayBuffer());

  let parsed;
  try {
    parsed = parseSbom(buf, file.name);
  } catch (err) {
    if (err instanceof SbomParseError) {
      sbomUploads.inc({ format: 'unknown', status: 'parse_error' });
      return NextResponse.json({ error: err.message }, { status: 400 });
    }
    throw err;
  }

  const analysis = await prisma.analysis.create({
    data: {
      ownerId: auth.id,
      filename: file.name,
      format: parsed.format,
      specVersion: parsed.specVersion,
      status: 'PARSING',
      componentCount: parsed.components.length,
      rawSbom: JSON.parse(buf.toString('utf8')),
      components: {
        create: parsed.components.map((c) => ({
          purl: c.purl,
          name: c.name,
          version: c.version,
          ecosystem: c.ecosystem,
          licenses: c.licenses,
        })),
      },
    },
  });

  void runScan(analysis.id, parsed.components, parsed.format);

  sbomUploads.inc({ format: parsed.format, status: 'accepted' });
  return NextResponse.json({
    analysisId: analysis.id,
    format: parsed.format,
    componentCount: parsed.components.length,
    status: 'PARSING',
  });
}
