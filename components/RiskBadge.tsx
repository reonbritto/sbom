import { cn } from '@/lib/utils';

interface Props {
  score: number | null | undefined;
  band?: string | null;
  compact?: boolean;
}

export function RiskBadge({ score, band, compact }: Props) {
  if (score === null || score === undefined) return <span className="text-muted-foreground">—</span>;
  const tier = band ?? deriveBand(score);

  const cls = cn(
    'inline-flex items-center justify-center rounded-full border px-2.5 py-0.5 text-xs font-bold tabular-nums',
    tier === 'critical' && 'border-critical bg-critical/15 text-critical',
    tier === 'high' && 'border-high bg-high/15 text-high',
    tier === 'moderate' && 'border-medium bg-medium/15 text-medium',
    tier === 'low' && 'border-low bg-low/15 text-low',
    tier === 'none' && 'border-border text-muted-foreground',
  );

  if (compact) return <span className={cls}>{score}</span>;
  return <span className={cls} title="Composite risk score (CVSS + EPSS + reputation, 0–100)">Risk {score}</span>;
}

function deriveBand(score: number): string {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'moderate';
  if (score >= 10) return 'low';
  return 'none';
}
