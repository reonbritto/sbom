'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { UploadCloud } from 'lucide-react';
import { cn } from '@/lib/utils';

export function SbomUploader() {
  const router = useRouter();
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function uploadFile(file: File) {
    setError(null);
    setUploading(true);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch('/api/sbom/upload', { method: 'POST', body: fd });
      const json = await res.json();
      if (!res.ok) {
        setError(json.error ?? 'Upload failed');
        setUploading(false);
        return;
      }
      router.push(`/analyses/${json.analysisId}`);
    } catch (err) {
      setError((err as Error).message);
      setUploading(false);
    }
  }

  return (
    <div>
      <label
        className={cn(
          'flex flex-col items-center justify-center cursor-pointer rounded-xl border-2 border-dashed border-border px-6 py-12 transition-colors',
          dragging && 'border-primary bg-primary/5',
        )}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const f = e.dataTransfer.files[0];
          if (f) void uploadFile(f);
        }}
      >
        <UploadCloud size={36} className="text-primary" />
        <div className="mt-3 font-medium">{uploading ? 'Uploading and parsing…' : 'Drop a CycloneDX or SPDX JSON file here'}</div>
        <div className="text-xs text-muted-foreground mt-1">or click to choose a file</div>
        <input type="file" accept=".json,application/json" className="hidden"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) void uploadFile(f); }} disabled={uploading} />
      </label>
      {error && <div className="mt-3 text-sm text-critical">{error}</div>}
    </div>
  );
}
