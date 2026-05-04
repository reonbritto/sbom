'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { ShieldAlert, Wrench } from 'lucide-react';
import { SeverityBadge } from './SeverityBadge';
import { EpssBadge } from './EpssBadge';
import { RiskBadge } from './RiskBadge';
import { Input } from './ui/input';
import { Select } from './ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { compareSeverity } from '@/lib/analytics';
import { cn } from '@/lib/utils';
import type { Severity } from '@/lib/types';

interface Row {
  id: string;
  purl: string;
  name: string;
  version: string;
  ecosystem: string | null;
  licenses: unknown;
  vulnCount: number;
  maxSeverity: string | null;
  maxEpss: number | null;
  isMalicious: boolean;
  riskScore: number;
  riskBand: string | null;
  recommendedFix: string | null;
}

function encodePurl(purl: string): string {
  return Buffer.from(purl, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function ComponentTable({ analysisId, components }: { analysisId: string; components: Row[] }) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [maliciousOnly, setMaliciousOnly] = useState(false);
  const [sort, setSort] = useState<keyof Row>('riskScore');
  const [asc, setAsc] = useState(false);

  const filtered = useMemo(() => {
    const s = search.toLowerCase();
    let rows = components.filter((c) => !s || c.name.toLowerCase().includes(s) || c.purl.toLowerCase().includes(s));
    if (severityFilter) rows = rows.filter((r) => (r.maxSeverity ?? 'NONE') === severityFilter);
    if (maliciousOnly) rows = rows.filter((r) => r.isMalicious);
    rows = [...rows].sort((a, b) => {
      if (sort === 'maxSeverity') {
        const cmp = compareSeverity(a.maxSeverity as Severity | null, b.maxSeverity as Severity | null);
        return asc ? -cmp : cmp;
      }
      const av = a[sort]; const bv = b[sort];
      if (av === bv) return 0;
      if (av === null || av === undefined) return 1;
      if (bv === null || bv === undefined) return -1;
      const cmp = av < bv ? -1 : 1;
      return asc ? cmp : -cmp;
    });
    return rows;
  }, [components, search, severityFilter, maliciousOnly, sort, asc]);

  function toggleSort(field: keyof Row) {
    if (sort === field) setAsc(!asc);
    else { setSort(field); setAsc(false); }
  }

  const maliciousCount = components.filter((c) => c.isMalicious).length;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Input className="max-w-xs" placeholder="Search by name or purl…" value={search} onChange={(e) => setSearch(e.target.value)} />
        <Select className="max-w-[180px]" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="NONE">None</option>
        </Select>
        {maliciousCount > 0 && (
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={maliciousOnly} onChange={(e) => setMaliciousOnly(e.target.checked)} />
            <span>Malicious only ({maliciousCount})</span>
          </label>
        )}
        <span className="text-xs text-muted-foreground ml-auto">{filtered.length} components</span>
      </div>
      <div className="rounded-xl border border-border overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="cursor-pointer" onClick={() => toggleSort('riskScore')}>Risk</TableHead>
              <TableHead className="cursor-pointer" onClick={() => toggleSort('name')}>Name</TableHead>
              <TableHead className="cursor-pointer" onClick={() => toggleSort('version')}>Version</TableHead>
              <TableHead className="cursor-pointer" onClick={() => toggleSort('ecosystem')}>Ecosystem</TableHead>
              <TableHead className="cursor-pointer" onClick={() => toggleSort('vulnCount')}>Vulns</TableHead>
              <TableHead className="cursor-pointer" onClick={() => toggleSort('maxSeverity')}>Severity</TableHead>
              <TableHead className="cursor-pointer" onClick={() => toggleSort('maxEpss')}>EPSS</TableHead>
              <TableHead>Fix</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((c) => (
              <TableRow key={c.id} className={cn(c.isMalicious && 'bg-critical/5')}>
                <TableCell><RiskBadge score={c.riskScore} band={c.riskBand} compact /></TableCell>
                <TableCell>
                  <span className="inline-flex items-center gap-1.5">
                    {c.isMalicious && <ShieldAlert size={14} className="text-critical" />}
                    <Link href={`/analyses/${analysisId}/components/${encodePurl(c.purl)}`} className="text-primary hover:underline">{c.name}</Link>
                  </span>
                </TableCell>
                <TableCell className="tabular-nums">{c.version || '—'}</TableCell>
                <TableCell className="text-muted-foreground">{c.ecosystem ?? 'unknown'}</TableCell>
                <TableCell className="tabular-nums">{c.vulnCount}</TableCell>
                <TableCell><SeverityBadge severity={c.maxSeverity} /></TableCell>
                <TableCell><EpssBadge score={c.maxEpss} compact /></TableCell>
                <TableCell>
                  {c.recommendedFix ? (
                    <span className="inline-flex items-center gap-1 text-xs">
                      <Wrench size={12} className="text-low" />
                      <code className="rounded bg-muted px-1.5 py-0.5">{c.recommendedFix}</code>
                    </span>
                  ) : '—'}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
