import { cn } from '@/lib/utils';

interface Props {
  score: number | null | undefined;
  percentile?: number | null;
  compact?: boolean;
}

export function EpssBadge({ score, percentile, compact }: Props) {
  if (score === null || score === undefined) return <span className="text-muted-foreground">—</span>;
  const pct = (score * 100).toFixed(score >= 0.1 ? 1 : 2);
  const tier = !percentile ? 'low' : percentile >= 0.95 ? 'urgent' : percentile >= 0.5 ? 'elevated' : 'low';

  const cls = cn(
    'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold tabular-nums',
    tier === 'urgent' && 'border-critical/50 bg-critical/15 text-critical',
    tier === 'elevated' && 'border-high/50 bg-high/15 text-high',
    tier === 'low' && 'border-border bg-muted text-muted-foreground',
  );

  if (compact) {
    return <span className={cls} title={percentile ? `${(percentile * 100).toFixed(0)}th percentile` : undefined}>{pct}%</span>;
  }
  return (
    <span className={cls} title="EPSS — exploit probability over the next 30 days">
      EPSS {pct}%
      {percentile !== null && percentile !== undefined && (
        <span className="opacity-70 font-normal"> · p{(percentile * 100).toFixed(0)}</span>
      )}
    </span>
  );
}
