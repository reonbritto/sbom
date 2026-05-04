import { Badge } from './ui/badge';
import type { Severity } from '@/lib/types';

const VARIANT: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'none'> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  NONE: 'none',
};

export function SeverityBadge({ severity }: { severity: Severity | string | null | undefined }) {
  const sev = (severity ?? 'NONE').toUpperCase();
  const variant = VARIANT[sev] ?? 'none';
  return <Badge variant={variant}>{sev}</Badge>;
}
