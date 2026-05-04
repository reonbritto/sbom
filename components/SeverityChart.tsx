import type { SeverityDistribution } from '@/lib/types';

const COLORS: Record<keyof SeverityDistribution, string> = {
  CRITICAL: 'hsl(var(--critical))',
  HIGH: 'hsl(var(--high))',
  MEDIUM: 'hsl(var(--medium))',
  LOW: 'hsl(var(--low))',
  NONE: 'hsl(var(--muted-foreground))',
};

export function SeverityChart({ distribution }: { distribution: SeverityDistribution }) {
  const total = Object.values(distribution).reduce((a, b) => a + b, 0) || 1;
  const order: (keyof SeverityDistribution)[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];
  return (
    <div>
      <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted mb-3">
        {order.map((k) => (
          <div key={k} style={{ width: `${(distribution[k] / total) * 100}%`, background: COLORS[k] }} title={`${k}: ${distribution[k]}`} />
        ))}
      </div>
      <div className="flex flex-wrap gap-3 text-xs">
        {order.map((k) => (
          <div key={k} className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: COLORS[k] }} />
            <span className="text-muted-foreground">{k}</span>
            <span className="tabular-nums">{distribution[k]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
