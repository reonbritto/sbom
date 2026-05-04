import { Card, CardContent } from './ui/card';
import { cn } from '@/lib/utils';

export function StatCard({
  label,
  value,
  accent,
  className,
}: {
  label: string;
  value: string | number;
  accent?: string;
  className?: string;
}) {
  return (
    <Card className={className}>
      <CardContent className="p-4">
        <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
        <div className={cn('text-2xl font-semibold mt-1.5 tabular-nums', accent)}>{value}</div>
      </CardContent>
    </Card>
  );
}
