'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Sparkles } from 'lucide-react';
import { Button } from './ui/button';

export function DemoButton({ label = 'Load demo SBOM', variant = 'outline' }: { label?: string; variant?: 'default' | 'outline' | 'ghost' }) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadDemo() {
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/sbom/demo', { method: 'POST' });
      const json = await res.json();
      if (!res.ok) {
        setError(json.error ?? 'Failed to load demo');
        setLoading(false);
        return;
      }
      router.push(`/analyses/${json.analysisId}`);
    } catch (err) {
      setError((err as Error).message);
      setLoading(false);
    }
  }

  return (
    <span className="inline-flex items-center gap-2">
      <Button variant={variant} size="sm" onClick={loadDemo} disabled={loading}>
        <Sparkles size={14} />
        {loading ? 'Loading…' : label}
      </Button>
      {error && <span className="text-xs text-critical">{error}</span>}
    </span>
  );
}
