import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { ShieldAlert, Flame, Zap } from 'lucide-react';
import { prisma } from '@/lib/db';
import { getSessionUser } from '@/lib/auth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { OverviewDonuts } from '@/components/OverviewDonuts';
import { ComponentTable } from '@/components/ComponentTable';
import { DemoBadge } from '@/components/DemoBadge';
import { DeleteButton } from '@/components/DeleteButton';
import { StatusBadge } from '@/components/StatusBadge';
import { ExportMenu } from '@/components/ExportMenu';
import { AnalysisProgress } from '@/components/AnalysisProgress';
import { QualityIssuesPanel } from '@/components/QualityIssuesPanel';
import { lintSbom, summarizeIssues } from '@/lib/quality-linter';
import type { Severity, SeverityDistribution } from '@/lib/types';

export const dynamic = 'force-dynamic';

function encodePurl(purl: string): string {
  return Buffer.from(purl, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export default async function AnalysisDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const user = await getSessionUser();
  if (!user) redirect('/');

  const { id } = await params;
  const analysis = await prisma.analysis.findFirst({
    where: { id, ownerId: user.id },
    include: {
      components: {
        include: { vulnerabilities: { select: { severity: true, epssScore: true, epssPercentile: true } } },
      },
    },
  });
  if (!analysis) notFound();

  const distribution: SeverityDistribution = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
  let urgentEpssVulns = 0;
  const vulnDistribution: SeverityDistribution = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
  for (const c of analysis.components) {
    const sev = (c.maxSeverity ?? 'NONE') as Severity;
    distribution[sev] += 1;
    for (const v of c.vulnerabilities) {
      vulnDistribution[(v.severity ?? 'NONE') as Severity] += 1;
      if (v.epssPercentile && v.epssPercentile >= 0.95) urgentEpssVulns += 1;
    }
  }
  const totalVulns = Object.values(vulnDistribution).reduce((s, n) => s + n, 0);
  const maliciousComponents = analysis.components.filter((c) => c.isMalicious);
  const kevComponents = analysis.components.filter((c) => c.hasKev);

  // Component breakdown by ecosystem
  const ecoCount = new Map<string, number>();
  for (const c of analysis.components) {
    const eco = c.ecosystem ?? 'unknown';
    ecoCount.set(eco, (ecoCount.get(eco) ?? 0) + 1);
  }
  const ECO_PALETTE = ['#6aa3ff', '#ffcf56', '#6dd3a8', '#ff8c42', '#ff4d6d', '#a78bfa', '#22d3ee', '#84cc16'];
  const componentBreakdown = Array.from(ecoCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([label, value], i) => ({ label, value, color: ECO_PALETTE[i % ECO_PALETTE.length] }));

  // License breakdown
  const licCount = new Map<string, number>();
  for (const c of analysis.components) {
    const arr = Array.isArray(c.licenses) ? (c.licenses as string[]) : [];
    if (arr.length === 0) licCount.set('Unknown', (licCount.get('Unknown') ?? 0) + 1);
    for (const l of arr) licCount.set(l, (licCount.get(l) ?? 0) + 1);
  }
  const LIC_PALETTE = ['#6dd3a8', '#6aa3ff', '#ffcf56', '#a78bfa', '#ff8c42', '#22d3ee', '#84cc16', '#ff4d6d'];
  const licenseBreakdown = Array.from(licCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([label, value], i) => ({ label, value, color: LIC_PALETTE[i % LIC_PALETTE.length] }));
  const licenseTotal = Array.from(licCount.values()).reduce((s, n) => s + n, 0);

  // Vulnerabilities donut
  const vulnSlices = [
    { label: 'Critical', value: vulnDistribution.CRITICAL, color: 'hsl(var(--critical))' },
    { label: 'High', value: vulnDistribution.HIGH, color: 'hsl(var(--high))' },
    { label: 'Medium', value: vulnDistribution.MEDIUM, color: 'hsl(var(--medium))' },
    { label: 'Low', value: vulnDistribution.LOW, color: 'hsl(var(--low))' },
    { label: 'None', value: vulnDistribution.NONE, color: 'hsl(var(--muted-foreground))' },
  ].filter((s) => s.value > 0);

  // Quality issues
  const qualityIssues = lintSbom(analysis.rawSbom);
  const qualitySummary = summarizeIssues(qualityIssues);
  const qualitySlices = [
    { label: 'Critical', value: qualitySummary.byBand.critical, color: 'hsl(var(--critical))' },
    { label: 'High', value: qualitySummary.byBand.high, color: 'hsl(var(--high))' },
    { label: 'Medium', value: qualitySummary.byBand.medium, color: 'hsl(var(--medium))' },
    { label: 'Low', value: qualitySummary.byBand.low, color: 'hsl(var(--low))' },
  ].filter((s) => s.value > 0);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">{analysis.filename}</h1>
            {analysis.isDemo && <DemoBadge />}
            <Badge variant="outline" className="text-[10px] uppercase">{analysis.format} {analysis.specVersion}</Badge>
            <StatusBadge status={analysis.status} />
          </div>
          <div className="text-xs text-muted-foreground mt-1">
            Created {new Date(analysis.createdAt).toLocaleString()} · ID {analysis.id.slice(0, 8)}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="ghost" size="sm"><Link href="/">Back</Link></Button>
          <ExportMenu analysisId={analysis.id} filename={analysis.filename} />
          <DeleteButton analysisId={analysis.id} redirectTo="/" filename={analysis.filename} />
        </div>
      </div>

      <AnalysisProgressWrapper analysisId={analysis.id} status={analysis.status} />

      {kevComponents.length > 0 && (
        <Card className="border-critical/50 bg-critical/10">
          <CardContent className="p-4 flex items-start gap-3">
            <Zap size={20} className="text-critical shrink-0 mt-0.5" fill="currentColor" />
            <div>
              <div className="font-semibold">{kevComponents.length} component{kevComponents.length > 1 ? 's' : ''} contain CISA Known Exploited Vulnerabilities (KEV)</div>
              <div className="text-sm mt-1">Actively exploited in the wild — federal agencies must remediate by deadline.</div>
            </div>
          </CardContent>
        </Card>
      )}

      {maliciousComponents.length > 0 && (
        <Card className="border-critical/50 bg-critical/10">
          <CardContent className="p-4 flex items-start gap-3">
            <ShieldAlert size={20} className="text-critical shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <div className="font-semibold">{maliciousComponents.length} suspicious package{maliciousComponents.length > 1 ? 's' : ''} detected</div>
              <div className="text-sm mt-1">
                {maliciousComponents.slice(0, 5).map((c, i) => (
                  <span key={c.id}>
                    {i > 0 && ', '}
                    <Link href={`/analyses/${analysis.id}/components/${encodePurl(c.purl)}`} className="text-primary hover:underline">{c.name}@{c.version}</Link>
                  </span>
                ))}
                {maliciousComponents.length > 5 && ` and ${maliciousComponents.length - 5} more`}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {urgentEpssVulns > 0 && (
        <Card className="border-high/50 bg-high/10">
          <CardContent className="p-4 flex items-center gap-3">
            <Flame size={18} className="text-high" />
            <span className="text-sm">{urgentEpssVulns} vulnerabilit{urgentEpssVulns === 1 ? 'y' : 'ies'} in the top 5% most-likely-to-be-exploited (EPSS p95+). Treat as priority patches.</span>
          </CardContent>
        </Card>
      )}

      <OverviewDonuts
        componentCount={analysis.componentCount}
        componentBreakdown={componentBreakdown}
        qualityIssues={qualitySlices}
        qualityTotal={qualityIssues.length}
        vulnerabilities={vulnSlices}
        vulnTotal={totalVulns}
        licenses={licenseBreakdown}
        licenseTotal={licenseTotal}
      />

      <QualityIssuesPanel issues={qualityIssues} filename={analysis.filename} />

      <Card>
        <CardHeader><CardTitle>Components</CardTitle></CardHeader>
        <CardContent className="pt-0">
          <ComponentTable
            analysisId={analysis.id}
            components={analysis.components.map((c) => ({
              id: c.id, purl: c.purl, name: c.name, version: c.version,
              ecosystem: c.ecosystem, licenses: c.licenses,
              vulnCount: c.vulnCount, maxSeverity: c.maxSeverity, maxEpss: c.maxEpss,
              isMalicious: c.isMalicious, riskScore: c.riskScore, riskBand: c.riskBand,
              recommendedFix: c.recommendedFix,
            }))}
          />
        </CardContent>
      </Card>
    </div>
  );
}

function AnalysisProgressWrapper({ analysisId, status }: { analysisId: string; status: string }) {
  if (status === 'COMPLETE' || status === 'ERROR') return null;
  return <AnalysisProgress analysisId={analysisId} initialStatus={status} />;
}
