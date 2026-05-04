import { ExternalLink } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import type { QualityIssue, QualitySeverity } from '@/lib/quality-linter';

const SEVERITY_VARIANT: Record<QualitySeverity, 'critical' | 'high' | 'medium' | 'low'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
};

export function QualityIssuesPanel({ issues, filename }: { issues: QualityIssue[]; filename: string }) {
  if (issues.length === 0) {
    return (
      <Card>
        <CardHeader><CardTitle>Quality Issues</CardTitle></CardHeader>
        <CardContent className="text-sm text-muted-foreground">No quality issues detected. This SBOM meets NTIA Minimum Elements and basic hygiene requirements.</CardContent>
      </Card>
    );
  }
  return (
    <Card>
      <CardHeader><CardTitle>Quality Issues</CardTitle></CardHeader>
      <CardContent className="space-y-3 pt-0">
        {issues.map((issue) => (
          <div key={issue.id} className="rounded-lg border border-border p-4">
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div className="min-w-0">
                <div className="text-xs text-muted-foreground">{issue.title}</div>
                <div className="font-semibold mt-1">{issue.detail}</div>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <Badge variant="outline">{issue.category}</Badge>
                <Badge variant={SEVERITY_VARIANT[issue.severity]}>{issue.severity.toUpperCase()} ({issue.count})</Badge>
              </div>
            </div>
            <div className="flex items-center justify-between mt-3 text-xs">
              <span className="text-muted-foreground">{filename}</span>
              {issue.learnMoreUrl && (
                <a className="text-primary hover:underline inline-flex items-center gap-1" href={issue.learnMoreUrl} target="_blank" rel="noreferrer">
                  Learn more <ExternalLink size={11} />
                </a>
              )}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
