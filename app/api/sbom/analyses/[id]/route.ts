import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { isUnauthorized, requireUser } from '@/lib/auth';

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;
  const { id } = await params;

  const analysis = await prisma.analysis.findFirst({
    where: { id, ownerId: auth.id },
    select: {
      id: true,
      filename: true,
      format: true,
      specVersion: true,
      status: true,
      componentCount: true,
      vulnerableCount: true,
      createdAt: true,
    },
  });
  if (!analysis) return NextResponse.json({ error: 'not found' }, { status: 404 });
  return NextResponse.json(analysis);
}

export async function DELETE(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;
  const { id } = await params;

  const result = await prisma.analysis.deleteMany({ where: { id, ownerId: auth.id } });
  if (result.count === 0) return NextResponse.json({ error: 'not found' }, { status: 404 });
  return NextResponse.json({ deleted: true });
}
