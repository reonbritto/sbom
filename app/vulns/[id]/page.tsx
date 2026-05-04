import { notFound, redirect } from 'next/navigation';
import { Zap } from 'lucide-react';
import { getSessionUser } from '@/lib/auth';
import { getVuln } from '@/lib/osv-client';
import { summarizeVuln } from '@/lib/analytics';
import { extractCveIds, getEpssBatch, epssPriority } from '@/lib/epss-client';
import { isOsvMaliciousId } from '@/lib/malicious-detector';
import { enrichWithNvd } from '@/lib/nvd-client';
import { mapCweToAttack, tacticsCovered } from '@/lib/attack-mapping';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge } from '@/components/SeverityBadge';
import { EpssBadge } from '@/components/EpssBadge';
import { KevBadge } from '@/components/KevBadge';
import { MaliciousBanner } from '@/components/MaliciousBanner';
import { Markdown } from '@/components/Markdown';

export const dynamic = 'force-dynamic';

export default async function VulnDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const user = await getSessionUser();
  if (!user) redirect('/');

  const { id } = await params;
  const vuln = await getVuln(id);
  if (!vuln) notFound();
  const summary = summarizeVuln(vuln);

  const cveIds = extractCveIds(vuln.aliases, vuln.id);
  const epssMap = await getEpssBatch(cveIds);
  let bestEpss: { cve: string; epss: number; percentile: number; date: string } | null = null;
  for (const cve of cveIds) {
    const e = epssMap.get(cve);
    if (e && (bestEpss === null || e.epss > bestEpss.epss)) bestEpss = e;
  }
  const priority = epssPriority(bestEpss);
  const malicious = isOsvMaliciousId(vuln.id);
  const nvd = await enrichWithNvd(vuln);
  const attackMappings = nvd ? mapCweToAttack(nvd.cweIds) : [];
  const tactics = tacticsCovered(attackMappings);

  return (
    <div className="space-y-6">
      {malicious && <MaliciousBanner reason="osv_malicious" detail={`This advisory (${vuln.id}) is from OSV's confirmed malicious-packages dataset. Treat installation as a supply-chain compromise.`} />}

      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{vuln.id}</h1>
        <div className="flex flex-wrap items-center gap-2 mt-2">
          <SeverityBadge severity={summary.severity} />
          {typeof summary.cvssScore === 'number' && <span className="font-semibold">CVSS {summary.cvssScore.toFixed(1)}</span>}
          {bestEpss && <EpssBadge score={bestEpss.epss} percentile={bestEpss.percentile} />}
          {nvd?.knownExploited && <KevBadge dueDate={nvd.knownExploitedDueDate ?? undefined} />}
          {nvd?.cveId && <a href={`/cve/${nvd.cveId}`} className="rounded border border-border bg-muted px-1.5 py-0.5 text-xs font-mono text-primary hover:bg-primary hover:text-primary-foreground">{nvd.cveId}</a>}
          {summary.cvssVector && <code className="text-xs text-muted-foreground">{summary.cvssVector}</code>}
        </div>
        {vuln.aliases?.length ? <div className="text-xs text-muted-foreground mt-2">Aliases: {vuln.aliases.join(', ')}</div> : null}
        {nvd && nvd.cweIds.length > 0 && (
          <div className="text-sm mt-2 flex flex-wrap items-center gap-1">
            <span className="text-muted-foreground">Weaknesses:</span>
            {nvd.cweIds.map((c) => (
              <a key={c} href={`https://cwe.mitre.org/data/definitions/${c.replace(/^CWE-/, '')}.html`} target="_blank" rel="noreferrer" className="rounded border border-medium/40 bg-medium/10 px-1.5 py-0.5 text-xs font-mono text-medium hover:underline">{c}</a>
            ))}
          </div>
        )}
      </div>

      {nvd?.knownExploited && (
        <Card className="border-critical/50 bg-critical/10">
          <CardContent className="p-4 flex items-start gap-3">
            <Zap size={20} className="text-critical shrink-0 mt-0.5" fill="currentColor" />
            <div>
              <div className="font-semibold">CISA Known Exploited Vulnerability</div>
              <div className="text-sm mt-1">
                Added to CISA KEV catalog{nvd.knownExploitedDate ? ` on ${new Date(nvd.knownExploitedDate).toLocaleDateString()}` : ''}.
                {nvd.knownExploitedDueDate && ` Federal agencies must remediate by ${new Date(nvd.knownExploitedDueDate).toLocaleDateString()}.`}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {priority === 'urgent' && (
        <Card className="border-high/50 bg-high/10">
          <CardContent className="p-4 text-sm">
            ⚠️ EPSS percentile {((bestEpss?.percentile ?? 0) * 100).toFixed(0)}th — top 5% most-likely-to-be-exploited. Prioritize patching.
          </CardContent>
        </Card>
      )}

      {vuln.summary && (
        <Card>
          <CardHeader><CardTitle>Summary</CardTitle></CardHeader>
          <CardContent className="pt-0">
            <p className="mt-0">{vuln.summary}</p>
            {vuln.details && <Markdown source={vuln.details} />}
          </CardContent>
        </Card>
      )}

      {bestEpss && (
        <Card>
          <CardHeader><CardTitle>Exploit prediction (EPSS)</CardTitle></CardHeader>
          <CardContent className="pt-0">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-xs uppercase text-muted-foreground">Probability of exploit (next 30 days)</div>
                <div className="text-2xl font-semibold tabular-nums mt-1">{(bestEpss.epss * 100).toFixed(2)}%</div>
              </div>
              <div>
                <div className="text-xs uppercase text-muted-foreground">Percentile vs all CVEs</div>
                <div className="text-2xl font-semibold tabular-nums mt-1">{(bestEpss.percentile * 100).toFixed(0)}th</div>
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-3">Source: <a href="https://www.first.org/epss" target="_blank" rel="noreferrer" className="text-primary hover:underline">FIRST.org EPSS</a>. Score date: {bestEpss.date}.</p>
          </CardContent>
        </Card>
      )}

      {attackMappings.length > 0 && (
        <Card>
          <CardHeader><CardTitle>MITRE ATT&amp;CK mapping</CardTitle></CardHeader>
          <CardContent className="pt-0 space-y-3">
            <p className="text-xs text-muted-foreground">How an attacker would weaponize this weakness. Mapped CWE → CAPEC → ATT&amp;CK techniques.</p>
            {tactics.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-muted-foreground">Tactics:</span>
                {tactics.map((t) => <Badge key={t} variant="outline">{t}</Badge>)}
              </div>
            )}
            <div className="space-y-3">
              {attackMappings.map((m) => (
                <div key={m.cwe} className="rounded border border-border bg-muted p-3">
                  <div>
                    <a className="rounded border border-medium/40 bg-medium/10 px-1.5 py-0.5 text-xs font-mono text-medium" href={`https://cwe.mitre.org/data/definitions/${m.cwe.replace('CWE-', '')}.html`} target="_blank" rel="noreferrer">{m.cwe}</a>
                    <span className="ml-2 text-sm">{m.cweName}</span>
                  </div>
                  {m.capec.length > 0 && (
                    <div className="mt-2 text-xs">
                      <span className="text-muted-foreground">Attack patterns: </span>
                      {m.capec.map((c) => <a key={c.id} href={`https://capec.mitre.org/data/definitions/${c.id.replace('CAPEC-', '')}.html`} target="_blank" rel="noreferrer" className="text-primary hover:underline mr-2">{c.id}</a>)}
                    </div>
                  )}
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {m.techniques.map((t) => (
                      <a key={t.id} href={t.url} target="_blank" rel="noreferrer" className="inline-flex gap-1.5 px-2 py-1 rounded bg-primary/10 border border-primary/30 text-xs hover:bg-primary/20" title={`${t.tactic} — ${t.name}`}>
                        <strong className="text-primary font-mono">{t.id}</strong> {t.name}
                      </a>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {summary.fixedVersions.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Fixed in</CardTitle></CardHeader>
          <CardContent className="pt-0 flex flex-wrap gap-2">
            {summary.fixedVersions.map((v) => <code key={v} className="rounded border border-border bg-muted px-2 py-1 text-xs">{v}</code>)}
          </CardContent>
        </Card>
      )}

      {(vuln.references?.length ?? 0) > 0 && (
        <Card>
          <CardHeader><CardTitle>References</CardTitle></CardHeader>
          <CardContent className="pt-0">
            <ul className="list-disc pl-5 space-y-1 text-sm">
              {vuln.references!.map((r) => (
                <li key={r.url}><a href={r.url} target="_blank" rel="noreferrer" className="text-primary hover:underline break-all">{r.url}</a> <span className="text-muted-foreground">({r.type})</span></li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
