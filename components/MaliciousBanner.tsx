import { ShieldAlert } from 'lucide-react';
import { Badge } from './ui/badge';

interface Props {
  reason?: string | null;
  detail?: string | null;
  confidence?: string | null;
}

const REASON_LABEL: Record<string, string> = {
  osv_malicious: 'Confirmed malicious package',
  depsdev_malicious: 'Confirmed malicious package',
  typosquat: 'Suspected typosquat',
  suspicious_name: 'Suspicious package name',
  unknown_package: 'Unknown package',
};

export function MaliciousBanner({ reason, detail, confidence }: Props) {
  const label = (reason && REASON_LABEL[reason]) ?? 'Flagged package';
  return (
    <div className="flex items-start gap-3 rounded-lg border border-critical/50 bg-critical/10 p-4">
      <ShieldAlert size={20} className="text-critical shrink-0 mt-0.5" />
      <div>
        <div className="font-semibold flex items-center gap-2">
          {label}
          {confidence && <Badge variant="outline" className="text-[10px] uppercase tracking-wide">{confidence} confidence</Badge>}
        </div>
        {detail && <div className="text-sm mt-1 opacity-95">{detail}</div>}
      </div>
    </div>
  );
}
