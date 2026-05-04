'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Loader2 } from 'lucide-react';
import { Card, CardContent } from './ui/card';

const STATUS_STEPS = ['PARSING', 'SCANNING', 'COMPLETE'];

export function AnalysisProgress({ analysisId, initialStatus }: { analysisId: string; initialStatus: string }) {
  const router = useRouter();
  const [status, setStatus] = useState(initialStatus);

  useEffect(() => {
    if (status === 'COMPLETE' || status === 'ERROR') return;
    let cancelled = false;
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/sbom/analyses/${analysisId}`, { cache: 'no-store' });
        if (!res.ok) return;
        const json = await res.json();
        if (cancelled) return;
        setStatus(json.status);
        if (json.status === 'COMPLETE' || json.status === 'ERROR') router.refresh();
      } catch { /* ignore */ }
    }, 2500);
    return () => { cancelled = true; clearInterval(interval); };
  }, [analysisId, status, router]);

  if (status === 'COMPLETE' || status === 'ERROR') return null;
  const step = STATUS_STEPS.indexOf(status);
  const pct = step >= 0 ? ((step + 0.5) / STATUS_STEPS.length) * 100 : 5;
  const label = status === 'PARSING'
    ? 'Parsing SBOM and extracting components…'
    : 'Scanning components against OSV.dev, EPSS, and deps.dev…';

  return (
    <Card className="border-primary/40 bg-primary/5">
      <CardContent className="p-4 flex items-center gap-3">
        <Loader2 size={18} className="spin text-primary" />
        <div className="flex-1 min-w-0">
          <div className="font-semibold">{label}</div>
          <div className="text-xs text-muted-foreground mt-1">Usually completes in 5–30 seconds.</div>
          <div className="mt-2 h-1.5 rounded-full bg-primary/20 overflow-hidden">
            <div className="h-full bg-primary transition-[width] duration-700" style={{ width: `${pct}%` }} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
