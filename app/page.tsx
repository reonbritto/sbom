import Link from 'next/link';
import { ShieldCheck, Zap, FileSearch, AlertTriangle, Wrench } from 'lucide-react';
import { prisma } from '@/lib/db';
import { getSessionUser } from '@/lib/auth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { StatCard } from '@/components/StatCard';
import { RiskBadge } from '@/components/RiskBadge';
import { StatusBadge } from '@/components/StatusBadge';
import { DemoBadge } from '@/components/DemoBadge';
import { DemoButton } from '@/components/DemoButton';
import { DeleteButton } from '@/components/DeleteButton';
import { LoginForm } from '@/components/LoginForm';

export const dynamic = 'force-dynamic';

export default async function HomePage() {
  const user = await getSessionUser();
  if (!user) return <SignedOutHome />;
  return <Dashboard userId={user.id} />;
}

function SignedOutHome() {
  return (
    <div className="-mx-6 -my-8 grid min-h-[calc(100vh-56px)] lg:grid-cols-2">
      <div className="flex flex-col items-center justify-center p-6 md:p-12">
        <div className="w-full max-w-sm space-y-6">
          <div className="flex items-center justify-center gap-2 text-muted-foreground text-sm font-semibold">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <span>SBOM Vulnerability Analyzer</span>
          </div>
          <LoginForm />
        </div>
      </div>

      <div className="relative hidden bg-muted lg:block overflow-hidden border-l border-border">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,hsl(var(--primary)/0.18),transparent_55%),radial-gradient(circle_at_75%_80%,hsl(var(--high)/0.12),transparent_60%)]" />
        <div className="relative z-10 flex h-full flex-col justify-center px-12 gap-8">
          <blockquote className="space-y-3">
            <p className="text-2xl leading-snug font-medium">
              Upload an SBOM. See every CVE, every exploited vulnerability, every supply-chain risk —
              <span className="text-primary"> in seconds</span>.
            </p>
            <footer className="text-sm text-muted-foreground">
              Backed by OSV.dev, FIRST EPSS, CISA KEV, NVD, deps.dev, and OpenSSF Scorecard.
            </footer>
          </blockquote>
          <div className="grid gap-4">
            <Highlight icon={<Zap className="h-4 w-4" fill="currentColor" />} title="CISA KEV alerts" body="Flag CVEs that are actively being exploited in the wild — with federal patch deadlines." />
            <Highlight icon={<FileSearch className="h-4 w-4" />} title="EPSS-aware triage" body="Real exploit probability per CVE. Patch the 6.5 with 91% chance, not the 9.8 with 0.04%." />
            <Highlight icon={<AlertTriangle className="h-4 w-4" />} title="Malicious package detection" body="Cross-references OSV's malicious-packages dataset and reputation-aware typosquat heuristics." />
            <Highlight icon={<Wrench className="h-4 w-4" />} title="One-version fix planner" body="Finds the single package version that resolves the most CVEs at once." />
          </div>
        </div>
      </div>
    </div>
  );
}

function Highlight({ icon, title, body }: { icon: React.ReactNode; title: string; body: string }) {
  return (
    <div className="flex items-start gap-3">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-card text-primary">
        {icon}
      </div>
      <div>
        <div className="text-sm font-medium">{title}</div>
        <div className="text-xs text-muted-foreground leading-relaxed">{body}</div>
      </div>
    </div>
  );
}

async function Dashboard({ userId }: { userId: string }) {
  const analyses = await prisma.analysis.findMany({
    where: { ownerId: userId },
    orderBy: { createdAt: 'desc' },
    take: 50,
  });

  const totalAnalyses = analyses.length;
  const totalComponents = analyses.reduce((s, a) => s + a.componentCount, 0);
  const totalVulnerable = analyses.reduce((s, a) => s + a.vulnerableCount, 0);
  const totalMalicious = analyses.reduce((s, a) => s + a.maliciousCount, 0);
  const peakRisk = analyses.reduce((m, a) => Math.max(m, a.riskScore), 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <div className="flex items-center gap-2">
          <DemoButton />
          <Button asChild><Link href="/upload">Upload SBOM</Link></Button>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard label="Peak risk" value={peakRisk} accent={peakRisk >= 60 ? 'text-critical' : peakRisk >= 35 ? 'text-high' : 'text-low'} />
        <StatCard label="Analyses" value={totalAnalyses} />
        <StatCard label="Components" value={totalComponents} />
        <StatCard label="Vulnerable" value={totalVulnerable} accent="text-high" />
        <StatCard label="Malicious" value={totalMalicious} accent="text-critical" />
      </div>

      <Card>
        <CardHeader><CardTitle>Recent analyses</CardTitle></CardHeader>
        <CardContent className="pt-0">
          {analyses.length === 0 ? (
            <p className="text-sm text-muted-foreground">No analyses yet. <DemoButton label="Try the demo" /> or upload your own SBOM.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Risk</TableHead>
                  <TableHead>Filename</TableHead>
                  <TableHead>Format</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Components</TableHead>
                  <TableHead>Vulnerable</TableHead>
                  <TableHead>Malicious</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {analyses.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell><RiskBadge score={a.riskScore} compact /></TableCell>
                    <TableCell>
                      <span className="inline-flex items-center gap-2">
                        <Link href={`/analyses/${a.id}`} className="text-primary hover:underline">{a.filename}</Link>
                        {a.isDemo && <DemoBadge />}
                      </span>
                    </TableCell>
                    <TableCell>{a.format} <span className="text-muted-foreground">{a.specVersion}</span></TableCell>
                    <TableCell><StatusBadge status={a.status} /></TableCell>
                    <TableCell className="tabular-nums">{a.componentCount}</TableCell>
                    <TableCell className="tabular-nums">{a.vulnerableCount}</TableCell>
                    <TableCell className="tabular-nums">{a.maliciousCount}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">{new Date(a.createdAt).toLocaleString()}</TableCell>
                    <TableCell><DeleteButton analysisId={a.id} variant="icon" filename={a.filename} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
