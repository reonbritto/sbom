'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Trash2 } from 'lucide-react';
import { Button } from './ui/button';

interface Props {
  analysisId: string;
  redirectTo?: string;
  variant?: 'outline' | 'ghost' | 'icon';
  label?: string;
  filename?: string;
}

export function DeleteButton({ analysisId, redirectTo, variant = 'outline', label = 'Delete', filename }: Props) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  async function onDelete(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    const what = filename ? `“${filename}”` : 'this analysis';
    if (!confirm(`Delete ${what}? This cannot be undone.`)) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/sbom/analyses/${analysisId}`, { method: 'DELETE' });
      if (!res.ok) {
        const json = await res.json().catch(() => ({}));
        alert(json.error ?? `Delete failed (HTTP ${res.status})`);
        setLoading(false);
        return;
      }
      if (redirectTo) router.push(redirectTo);
      else router.refresh();
    } catch (err) {
      alert((err as Error).message);
      setLoading(false);
    }
  }

  if (variant === 'icon') {
    return (
      <Button variant="ghost" size="icon" onClick={onDelete} disabled={loading} title="Delete analysis" aria-label="Delete">
        <Trash2 size={14} />
      </Button>
    );
  }

  return (
    <Button variant={variant} size="sm" onClick={onDelete} disabled={loading}>
      <Trash2 size={14} />
      {loading ? 'Deleting…' : label}
    </Button>
  );
}
