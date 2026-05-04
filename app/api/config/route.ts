import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({
    authProvider: 'better-auth',
    maxSbomBytes: parseInt(process.env.MAX_SBOM_BYTES ?? '10485760', 10),
    maxComponents: parseInt(process.env.MAX_COMPONENTS ?? '10000', 10),
  });
}
