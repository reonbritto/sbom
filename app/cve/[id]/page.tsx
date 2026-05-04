import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { Zap, ExternalLink } from 'lucide-react';
import { getSessionUser } from '@/lib/auth';
import { enrichByCveId } from '@/lib/nvd-client';
import { getEpssOne, epssPriority } from '@/lib/epss-client';
import { lookupKev } from '@/lib/kev-catalog';
import { mapCweToAttack, tacticsCovered } from '@/lib/attack-mapping';
import { bucketByCvss } from '@/lib/analytics';
import { prisma } from '@/lib/db';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { SeverityBadge } from '@/components/SeverityBadge';
import { EpssBadge } from '@/components/EpssBadge';
import { KevBadge } from '@/components/KevBadge';
import { Markdown } from '@/components/Markdown';

export const dynamic = 'force-dynamic';

export default async function CveDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const user = await getSessionUser();
  if (!user) redirect('/');
  const sub = user.id;

  const { id } = await params;
  const cveId = id.toUpperCase();
  if (!/^CVE-\d{4}-\d+$/.test(cveId)) notFound();

  const [nvd, epss, kev] = await Promise.all([enrichByCveId(cveId), getEpssOne(cveId), lookupKev(cveId)]);
  if (!nvd) notFound();

  const score = nvd.cvssV3Score ?? nvd.cvssV2Score ?? null;
  const severity = nvd.cvssV3Severity ?? bucketByCvss(score);
  const attackMappings = mapCweToAttack(nvd.cweIds);
  const tactics = tacticsCovered(attackMappings);
  const isKev = !!kev || nvd.knownExploited;

  const affectedComponents = await prisma.component.findMany({
    where: { analysis: { ownerId: sub }, vulnerabilities: { some: { primaryCve: cveId } } },
    select: { id: true, name: true, version: true, ecosystem: true, purl: true, analysisId: true, analysis: { select: { id: true, filename: true } } },
    take: 50,
  });

  return (
    <div className="space-y-6">
      <div>
        <div className="text-xs text-muted-foreground">Vulnerability detail</div>
        <h1 className="text-2xl font-semibold tracking-tight mt-1">{cveId}</h1>
        {nvd.knownExploitedVulnName && <div className="text-sm italic text-muted-foreground mt-1">{nvd.knownExploitedVulnName}</div>}
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <SeverityBadge severity={severity} />
          {typeof score === 'number' && <span className="font-semibold">CVSS {score.toFixed(1)}</span>}
          {epss && <EpssBadge score={epss.epss} percentile={epss.percentile} />}
          {isKev && <KevBadge dueDate={kev?.dueDate ?? nvd.knownExploitedDueDate ?? undefined} />}
          {nvd.vulnStatus && <Badge variant="outline">{nvd.vulnStatus}</Badge>}
        </div>
      </div>

      {isKev && (
        <Card className="border-critical/50 bg-critical/10">
          <CardContent className="p-4 flex items-start gap-3">
            <Zap size={20} className="text-critical shrink-0 mt-0.5" fill="currentColor" />
            <div>
              <div className="font-semibold">CISA Known Exploited Vulnerability</div>
              <div className="text-sm mt-1">
                {kev?.shortDescription ?? 'Confirmed exploited in the wild.'}
                {kev?.dueDate && ` Federal patch deadline: ${new Date(kev.dueDate).toLocaleDateString()}.`}
                {kev?.requiredAction && <div className="mt-2"><strong>Required action:</strong> {kev.requiredAction}</div>}
                {kev?.knownRansomwareCampaignUse && kev.knownRansomwareCampaignUse !== 'Unknown' && <div className="mt-1"><strong>Ransomware use:</strong> {kev.knownRansomwareCampaignUse}</div>}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card><CardContent className="p-4"><div className="text-xs uppercase text-muted-foreground">Published</div><div className="mt-1">{nvd.published ? new Date(nvd.published).toLocaleDateString() : '—'}</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-xs uppercase text-muted-foreground">Last modified</div><div className="mt-1">{nvd.lastModified ? new Date(nvd.lastModified).toLocaleDateString() : '—'}</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-xs uppercase text-muted-foreground">EPSS priority</div><div className="mt-1 capitalize">{epssPriority(epss) ?? '—'}</div></CardContent></Card>
        <Card><CardContent className="p-4"><div className="text-xs uppercase text-muted-foreground">Affected vendors</div><div className="mt-1 tabular-nums">{nvd.vendors.length}</div></CardContent></Card>
      </div>

      {nvd.description && (
        <Card>
          <CardHeader><CardTitle>Description</CardTitle></CardHeader>
          <CardContent className="pt-0"><Markdown source={nvd.description} /></CardContent>
        </Card>
      )}

      <Card>
        <CardHeader><CardTitle>CVSS</CardTitle></CardHeader>
        <CardContent className="pt-0 grid grid-cols-1 md:grid-cols-2 gap-4">
          {typeof nvd.cvssV3Score === 'number' && (
            <div>
              <div className="text-xs uppercase text-muted-foreground">CVSS v3 base</div>
              <div className="text-2xl font-semibold mt-1 tabular-nums">{nvd.cvssV3Score.toFixed(1)} <span className="text-sm text-muted-foreground font-normal">{nvd.cvssV3Severity}</span></div>
              <code className="text-[11px] text-muted-foreground break-all">{nvd.cvssV3Vector}</code>
            </div>
          )}
          {typeof nvd.cvssV2Score === 'number' && (
            <div>
              <div className="text-xs uppercase text-muted-foreground">CVSS v2 base</div>
              <div className="text-2xl font-semibold mt-1 tabular-nums">{nvd.cvssV2Score.toFixed(1)}</div>
              <code className="text-[11px] text-muted-foreground break-all">{nvd.cvssV2Vector}</code>
            </div>
          )}
        </CardContent>
      </Card>

      {epss && (
        <Card>
          <CardHeader><CardTitle>Exploit prediction (EPSS)</CardTitle></CardHeader>
          <CardContent className="pt-0 grid grid-cols-2 gap-4">
            <div><div className="text-xs uppercase text-muted-foreground">Probability of exploit (next 30 days)</div><div className="text-2xl font-semibold tabular-nums mt-1">{(epss.epss * 100).toFixed(2)}%</div></div>
            <div><div className="text-xs uppercase text-muted-foreground">Percentile vs all CVEs</div><div className="text-2xl font-semibold tabular-nums mt-1">{(epss.percentile * 100).toFixed(0)}th</div></div>
          </CardContent>
        </Card>
      )}

      {nvd.cweIds.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Weaknesses (CWE)</CardTitle></CardHeader>
          <CardContent className="pt-0 flex flex-wrap gap-2">
            {nvd.cweIds.map((c) => <a key={c} href={`https://cwe.mitre.org/data/definitions/${c.replace(/^CWE-/, '')}.html`} target="_blank" rel="noreferrer" className="rounded border border-medium/40 bg-medium/10 px-1.5 py-0.5 text-xs font-mono text-medium hover:underline">{c}</a>)}
          </CardContent>
        </Card>
      )}

      {attackMappings.length > 0 && (
        <Card>
          <CardHeader><CardTitle>MITRE ATT&amp;CK mapping</CardTitle></CardHeader>
          <CardContent className="pt-0 space-y-3">
            <p className="text-xs text-muted-foreground">How an attacker would weaponize this weakness.</p>
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
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {m.techniques.map((t) => (
                      <a key={t.id} href={t.url} target="_blank" rel="noreferrer" className="inline-flex gap-1.5 px-2 py-1 rounded bg-primary/10 border border-primary/30 text-xs hover:bg-primary/20"><strong className="text-primary font-mono">{t.id}</strong> {t.name}</a>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {affectedComponents.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Affected in your SBOMs ({affectedComponents.length})</CardTitle></CardHeader>
          <CardContent className="pt-0">
            <Table>
              <TableHeader>
                <TableRow><TableHead>Component</TableHead><TableHead>Version</TableHead><TableHead>Ecosystem</TableHead><TableHead>Analysis</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {affectedComponents.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell><Link href={`/analyses/${c.analysisId}/components/${encodePurl(c.purl)}`} className="text-primary hover:underline">{c.name}</Link></TableCell>
                    <TableCell>{c.version}</TableCell>
                    <TableCell className="text-muted-foreground">{c.ecosystem ?? 'unknown'}</TableCell>
                    <TableCell><Link href={`/analyses/${c.analysisId}`} className="text-primary hover:underline">{c.analysis.filename}</Link></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {nvd.vendors.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Affected vendors</CardTitle></CardHeader>
          <CardContent className="pt-0 flex flex-wrap gap-2">
            {nvd.vendors.slice(0, 30).map((v) => <Badge key={v} variant="outline">{v}</Badge>)}
          </CardContent>
        </Card>
      )}

      {nvd.references.length > 0 && (
        <Card>
          <CardHeader><CardTitle>References</CardTitle></CardHeader>
          <CardContent className="pt-0">
            <ul className="list-disc pl-5 space-y-1 text-sm">
              {nvd.references.map((r) => (
                <li key={r.url}>
                  <a href={r.url} target="_blank" rel="noreferrer" className="text-primary hover:underline break-all">{r.url}</a>
                  {r.tags.length > 0 && <span className="ml-2 text-xs text-muted-foreground">{r.tags.map((t) => <Badge key={t} variant="outline" className="mr-1 text-[10px]">{t}</Badge>)}</span>}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <div className="flex flex-wrap gap-3 text-sm">
        <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline"><ExternalLink size={12} /> View on NVD</a>
        <a href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline"><ExternalLink size={12} /> View on MITRE</a>
      </div>
    </div>
  );
}

function encodePurl(purl: string): string {
  return Buffer.from(purl, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
