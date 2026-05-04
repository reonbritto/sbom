import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { Wrench } from 'lucide-react';
import { getSessionUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge } from '@/components/SeverityBadge';
import { EpssBadge } from '@/components/EpssBadge';
import { RiskBadge } from '@/components/RiskBadge';
import { KevBadge } from '@/components/KevBadge';
import { MaliciousBanner } from '@/components/MaliciousBanner';
import { getReputation } from '@/lib/depsdev-client';

export const dynamic = 'force-dynamic';

function decodePurl(s: string): string {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
}

export default async function ComponentDetailPage({ params }: { params: Promise<{ id: string; purl: string }> }) {
  const user = await getSessionUser();
  if (!user) redirect('/');

  const { id, purl: encoded } = await params;
  const purl = decodePurl(encoded);

  const analysis = await prisma.analysis.findFirst({ where: { id, ownerId: user.id }, select: { id: true, filename: true } });
  if (!analysis) notFound();

  const component = await prisma.component.findFirst({
    where: { analysisId: id, purl },
    include: { vulnerabilities: { orderBy: [{ cvssScore: 'desc' }, { epssScore: 'desc' }] } },
  });
  if (!component) notFound();

  const reputation = await getReputation(component.ecosystem, component.name, component.version);
  const licenses = Array.isArray(component.licenses) ? (component.licenses as string[]) : [];
  const rationale = Array.isArray(component.riskRationale) ? (component.riskRationale as string[]) : [];

  return (
    <div className="space-y-6">
      <div>
        <Link href={`/analyses/${id}`} className="text-xs text-muted-foreground hover:underline">← {analysis.filename}</Link>
        <h1 className="text-2xl font-semibold tracking-tight mt-2">
          {component.name} <span className="text-muted-foreground">{component.version}</span>
        </h1>
        <code className="text-xs text-muted-foreground">{component.purl}</code>
      </div>

      {component.isMalicious && <MaliciousBanner reason={component.maliciousReason} detail={component.maliciousDetail} confidence={component.maliciousConfidence} />}

      {component.recommendedFix && (
        <Card className="border-low/50 bg-low/10">
          <CardContent className="p-4 flex items-center gap-3">
            <Wrench size={20} className="text-low shrink-0" />
            <div>
              <div className="font-semibold">Recommended fix</div>
              <div className="text-sm mt-1">Upgrade to <code className="rounded bg-muted px-1.5 py-0.5">{component.recommendedFix}</code> to resolve known vulnerabilities.</div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card><CardContent className="p-4"><div className="text-xs uppercase text-muted-foreground">Risk</div><div className="mt-2"><RiskBadge score={component.riskScore} band={component.riskBand} /></div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-xs uppercase text-muted-foreground">Ecosystem</div><div className="mt-2 text-base">{component.ecosystem ?? 'unknown'}</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-xs uppercase text-muted-foreground">Licenses</div><div className="mt-2 text-sm">{licenses.length ? licenses.join(', ') : '—'}</div></CardContent></Card>
        {component.scorecardScore !== null && (
          <Card><CardContent className="p-4"><div className="text-xs uppercase text-muted-foreground">OpenSSF Scorecard</div><div className="mt-2 text-xl font-semibold tabular-nums">{component.scorecardScore.toFixed(1)} <span className="text-sm font-normal text-muted-foreground">/ 10</span></div></CardContent></Card>
        )}
        {component.versionsCount && (
          <Card><CardContent className="p-4"><div className="text-xs uppercase text-muted-foreground">Releases</div><div className="mt-2 text-xl font-semibold tabular-nums">{component.versionsCount}</div></CardContent></Card>
        )}
      </div>

      {rationale.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Why this risk score</CardTitle></CardHeader>
          <CardContent className="pt-0"><ul className="list-disc pl-5 space-y-1 text-sm">{rationale.map((r) => <li key={r}>{r}</li>)}</ul></CardContent>
        </Card>
      )}

      {reputation && reputation.scorecardChecks.length > 0 && (
        <Card>
          <CardHeader><CardTitle>OpenSSF Scorecard checks</CardTitle></CardHeader>
          <CardContent className="pt-0">
            <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-3 text-xs">
              {reputation.scorecardChecks.map((c) => (
                <div key={c.name} className={`flex justify-between rounded border-l-4 px-3 py-2 bg-muted ${c.score < 4 ? 'border-critical' : c.score < 7 ? 'border-medium' : 'border-low'}`}>
                  <span>{c.name}</span>
                  <strong className="tabular-nums">{c.score}/10</strong>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader><CardTitle>Vulnerabilities ({component.vulnerabilities.length})</CardTitle></CardHeader>
        <CardContent className="pt-0">
          {component.vulnerabilities.length === 0 ? (
            <p className="text-sm text-muted-foreground">No known vulnerabilities for this component.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>CVE</TableHead>
                  <TableHead>CWE</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>CVSS</TableHead>
                  <TableHead>EPSS</TableHead>
                  <TableHead>Flags</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {component.vulnerabilities.map((v) => {
                  const cwes = Array.isArray(v.cweIds) ? (v.cweIds as string[]) : [];
                  return (
                    <TableRow key={v.vulnId}>
                      <TableCell><Link href={`/vulns/${v.vulnId}`} className="text-primary hover:underline">{v.vulnId}</Link></TableCell>
                      <TableCell>
                        {v.primaryCve ? (
                          <Link href={`/cve/${v.primaryCve}`} className="rounded border border-border bg-muted px-1.5 py-0.5 text-xs font-mono text-primary hover:bg-primary hover:text-primary-foreground">{v.primaryCve}</Link>
                        ) : <span className="text-muted-foreground">—</span>}
                      </TableCell>
                      <TableCell>
                        {cwes.length === 0 ? <span className="text-muted-foreground">—</span> : (
                          <div className="flex flex-wrap gap-1">
                            {cwes.slice(0, 3).map((c) => (
                              <a key={c} href={`https://cwe.mitre.org/data/definitions/${c.replace(/^CWE-/, '')}.html`} target="_blank" rel="noreferrer" className="rounded border border-medium/40 bg-medium/10 px-1.5 py-0.5 text-xs font-mono text-medium hover:underline">{c}</a>
                            ))}
                          </div>
                        )}
                      </TableCell>
                      <TableCell><SeverityBadge severity={v.severity} /></TableCell>
                      <TableCell className="tabular-nums">{v.cvssScore?.toFixed(1) ?? '—'}</TableCell>
                      <TableCell><EpssBadge score={v.epssScore} percentile={v.epssPercentile} compact /></TableCell>
                      <TableCell>
                        <span className="flex gap-1">
                          {v.isKev && <KevBadge dueDate={v.kevDueDate} />}
                          {v.isMalicious && <Badge variant="critical">MALICIOUS</Badge>}
                        </span>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
