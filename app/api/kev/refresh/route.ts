import { NextResponse } from 'next/server';
import { isUnauthorized, requireUser } from '@/lib/auth';
import { getKevMeta, refreshKevCatalog } from '@/lib/kev-catalog';

export async function POST() {
  const auth = await requireUser();
  if (isUnauthorized(auth)) return auth;
  const meta = await refreshKevCatalog(true);
  return NextResponse.json({ refreshed: !!meta, meta });
}

export async function GET() {
  const meta = await getKevMeta();
  return NextResponse.json({ meta });
}
