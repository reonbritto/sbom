import { Check, Loader2, AlertTriangle, Clock } from 'lucide-react';
import { Badge } from './ui/badge';

export function StatusBadge({ status }: { status: string }) {
  const cfg = configFor(status);
  const variant: 'low' | 'critical' | 'default' | 'medium' = cfg.tone;
  return (
    <Badge variant={variant} title={cfg.label}>
      <cfg.Icon size={11} className={cfg.spin ? 'spin' : undefined} />
      {cfg.label}
    </Badge>
  );
}

function configFor(status: string) {
  switch (status) {
    case 'COMPLETE': return { label: 'Complete', tone: 'low' as const, Icon: Check, spin: false };
    case 'ERROR': return { label: 'Error', tone: 'critical' as const, Icon: AlertTriangle, spin: false };
    case 'SCANNING': return { label: 'Scanning', tone: 'default' as const, Icon: Loader2, spin: true };
    case 'PARSING': return { label: 'Parsing', tone: 'default' as const, Icon: Loader2, spin: true };
    default: return { label: status, tone: 'medium' as const, Icon: Clock, spin: false };
  }
}
