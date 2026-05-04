'use client';

import { ChevronDown, FileDown, FileJson, FileText, Shield } from 'lucide-react';
import { Button } from './ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from './ui/dropdown-menu';

interface Props {
  analysisId: string;
  filename: string;
}

export function ExportMenu({ analysisId, filename }: Props) {
  const baseName = filename.replace(/\.[^.]+$/, '');

  function downloadFile(url: string, downloadName: string) {
    const a = document.createElement('a');
    a.href = url;
    a.download = downloadName;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          <FileDown size={14} /> Export <ChevronDown size={12} />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-[260px]">
        <DropdownMenuItem onSelect={() => window.open(`/api/sbom/analyses/${analysisId}/export/html`, '_blank')}>
          <FileText size={14} />
          <div>
            <div className="font-semibold">HTML / PDF report</div>
            <div className="text-xs text-muted-foreground">Print-ready, full findings</div>
          </div>
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => downloadFile(`/api/sbom/analyses/${analysisId}/export/json`, `${baseName}-report.json`)}>
          <FileJson size={14} />
          <div>
            <div className="font-semibold">JSON report</div>
            <div className="text-xs text-muted-foreground">Full structured dump</div>
          </div>
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => downloadFile(`/api/sbom/analyses/${analysisId}/export/vex`, `${baseName}-vex.json`)}>
          <Shield size={14} />
          <div>
            <div className="font-semibold">CycloneDX VEX</div>
            <div className="text-xs text-muted-foreground">Standard supply-chain format</div>
          </div>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
