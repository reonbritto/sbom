import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { isUnauthorized, requireUser } from '@/lib/auth';

export async function GET(req: NextRequest) {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;

  const limit = Math.min(parseInt(req.nextUrl.searchParams.get('limit') ?? '50', 10), 200);
  const analyses = await prisma.analysis.findMany({
    where: { ownerId: auth.id },
    orderBy: { createdAt: 'desc' },
    take: limit,
    select: {
      id: true,
      filename: true,
      format: true,
      specVersion: true,
      status: true,
      componentCount: true,
      vulnerableCount: true,
      maliciousCount: true,
      riskScore: true,
      isDemo: true,
      createdAt: true,
    },
  });
  return NextResponse.json({ analyses });
}
