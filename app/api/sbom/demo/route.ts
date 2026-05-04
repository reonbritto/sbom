import { NextResponse } from 'next/server';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { prisma } from '@/lib/db';
import { parseSbom, SbomParseError } from '@/lib/sbom-parser';
import { isUnauthorized, requireUser } from '@/lib/auth';
import { runScan } from '@/lib/scan';
import { sbomUploads } from '@/lib/metrics';

export async function POST() {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;

  let buf: Buffer;
  try {
    buf = await readFile(join(process.cwd(), 'data', 'demo-sbom.json'));
  } catch {
    try {
      buf = await readFile(join(process.cwd(), 'public', 'demo-sbom.json'));
    } catch {
      return NextResponse.json(
        { error: 'demo SBOM not bundled with this build' },
        { status: 500 },
      );
    }
  }

  let parsed;
  try {
    parsed = parseSbom(buf, 'demo-sbom.json');
  } catch (err) {
    if (err instanceof SbomParseError) {
      return NextResponse.json({ error: err.message }, { status: 500 });
    }
    throw err;
  }

  const analysis = await prisma.analysis.create({
    data: {
      ownerId: auth.id,
      filename: 'demo-sbom.json',
      format: parsed.format,
      specVersion: parsed.specVersion,
      status: 'PARSING',
      componentCount: parsed.components.length,
      isDemo: true,
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
  sbomUploads.inc({ format: parsed.format, status: 'demo' });

  return NextResponse.json({
    analysisId: analysis.id,
    format: parsed.format,
    componentCount: parsed.components.length,
    status: 'PARSING',
    isDemo: true,
  });
}
