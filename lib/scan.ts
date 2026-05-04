import { prisma } from './db';
import { scanComponents } from './osv-client';
import { bucketByCvss, extractCvssScore, maxSeverity } from './analytics';
import { sbomUploads } from './metrics';
import { extractCveIds, getEpssBatch } from './epss-client';
import { detectMalicious, isOsvMaliciousId } from './malicious-detector';
import { getReputation } from './depsdev-client';
import { computeRiskScore } from './risk-score';
import { planFix } from './fix-planner';
import { enrichWithNvd } from './nvd-client';
import { lookupKevBatch, refreshKevCatalog } from './kev-catalog';
import pLimit from 'p-limit';
import type { ParsedComponent, Severity } from './types';

const nvdLimit = pLimit(3);

export async function runScan(
  analysisId: string,
  components: ParsedComponent[],
  format: string,
): Promise<void> {
  try {
    await prisma.analysis.update({ where: { id: analysisId }, data: { status: 'SCANNING' } });

    const { byPurl, vulns } = await scanComponents(components);

    const allCveIds: string[] = [];
    for (const v of vulns.values()) allCveIds.push(...extractCveIds(v.aliases, v.id));
    const epssMap = await getEpssBatch(allCveIds);
    await refreshKevCatalog().catch(() => undefined);
    const kevMap = await lookupKevBatch(allCveIds);

    let vulnerableCount = 0;
    let maliciousCount = 0;
    let analysisRiskMax = 0;

    for (const dbComponent of await prisma.component.findMany({ where: { analysisId } })) {
      const refs = byPurl.get(dbComponent.purl) ?? [];
      const compVulns = refs
        .map((r) => vulns.get(r.id))
        .filter((v): v is NonNullable<typeof v> => Boolean(v));

      const reputation = await getReputation(
        dbComponent.ecosystem,
        dbComponent.name,
        dbComponent.version,
      );

      const severities: Severity[] = [];
      const writes: {
        vulnId: string;
        primaryCve: string | null;
        aliases: string[];
        cweIds: string[];
        severity: Severity;
        cvssScore: number | null;
        epssScore: number | null;
        epssPercentile: number | null;
        isMalicious: boolean;
        isKev: boolean;
        kevDueDate: Date | null;
      }[] = [];

      let maxEpss: number | null = null;
      let maxCvss: number | null = null;
      let osvMalicious = false;
      let hasKev = false;

      const nvdEnrichments = await Promise.all(
        compVulns.map((v) => nvdLimit(() => enrichWithNvd(v))),
      );

      for (let vi = 0; vi < compVulns.length; vi++) {
        const v = compVulns[vi];
        const enrichment = nvdEnrichments[vi];
        const { score: cvssScore } = extractCvssScore(v);
        if (cvssScore !== null && (maxCvss === null || cvssScore > maxCvss)) maxCvss = cvssScore;
        const sev = bucketByCvss(cvssScore);
        severities.push(sev);

        const cveIds = extractCveIds(v.aliases, v.id);
        const primaryCve = cveIds[0] ?? null;

        let epssScore: number | null = null;
        let epssPercentile: number | null = null;
        for (const cveId of cveIds) {
          const e = epssMap.get(cveId);
          if (e && (epssScore === null || e.epss > epssScore)) {
            epssScore = e.epss;
            epssPercentile = e.percentile;
          }
        }
        if (epssScore !== null && (maxEpss === null || epssScore > maxEpss)) maxEpss = epssScore;

        const malicious = isOsvMaliciousId(v.id);
        if (malicious) osvMalicious = true;

        let isKev = false;
        let kevDueDateValue: Date | null = null;
        for (const cveId of cveIds) {
          const kev = kevMap.get(cveId.toUpperCase());
          if (kev) {
            isKev = true;
            if (kev.dueDate) kevDueDateValue = new Date(kev.dueDate);
            break;
          }
        }
        if (!isKev && enrichment?.knownExploited) {
          isKev = true;
          if (enrichment.knownExploitedDueDate) kevDueDateValue = new Date(enrichment.knownExploitedDueDate);
        }
        if (isKev) hasKev = true;

        writes.push({
          vulnId: v.id,
          primaryCve,
          aliases: v.aliases ?? [],
          cweIds: enrichment?.cweIds ?? [],
          severity: sev,
          cvssScore,
          epssScore,
          epssPercentile,
          isMalicious: malicious,
          isKev,
          kevDueDate: kevDueDateValue,
        });
      }

      const finding = osvMalicious
        ? { reason: 'osv_malicious' as const, detail: 'Confirmed malicious advisory in OSV.', confidence: 'high' as const }
        : detectMalicious({ name: dbComponent.name, ecosystem: dbComponent.ecosystem, reputation });

      const risk = computeRiskScore({
        maxCvss,
        maxEpss,
        isMalicious: !!finding,
        hasKev,
        reputation,
        vulnCount: compVulns.length,
      });
      if (risk.score > analysisRiskMax) analysisRiskMax = risk.score;

      const fixPlan = compVulns.length > 0 ? planFix(dbComponent.version, compVulns) : null;

      const max = severities.length ? maxSeverity(severities) : null;
      if (compVulns.length > 0) vulnerableCount += 1;
      if (finding) maliciousCount += 1;

      await prisma.component.update({
        where: { id: dbComponent.id },
        data: {
          vulnCount: compVulns.length,
          maxSeverity: max,
          maxEpss,
          isMalicious: !!finding,
          maliciousReason: finding?.reason ?? null,
          maliciousDetail: finding?.detail ?? null,
          maliciousConfidence: finding?.confidence ?? null,
          scorecardScore: reputation?.openssfScorecard ?? null,
          versionsCount: reputation?.versionsCount ?? null,
          firstPublished: reputation?.firstPublished ? new Date(reputation.firstPublished) : null,
          recommendedFix: fixPlan?.recommendedVersion ?? null,
          hasKev,
          riskScore: risk.score,
          riskBand: risk.band,
          riskRationale: risk.rationale,
        },
      });

      if (writes.length > 0) {
        await prisma.componentVulnerability.createMany({
          data: writes.map((w) => ({
            componentId: dbComponent.id,
            vulnId: w.vulnId,
            primaryCve: w.primaryCve,
            aliases: w.aliases,
            cweIds: w.cweIds,
            severity: w.severity,
            cvssScore: w.cvssScore,
            epssScore: w.epssScore,
            epssPercentile: w.epssPercentile,
            isMalicious: w.isMalicious,
            isKev: w.isKev,
            kevDueDate: w.kevDueDate,
          })),
          skipDuplicates: true,
        });
      }
    }

    await prisma.analysis.update({
      where: { id: analysisId },
      data: { status: 'COMPLETE', vulnerableCount, maliciousCount, riskScore: analysisRiskMax },
    });
    sbomUploads.inc({ format, status: 'complete' });
  } catch (err) {
    console.error(`Scan failed for analysis ${analysisId}:`, err);
    await prisma.analysis
      .update({ where: { id: analysisId }, data: { status: 'ERROR' } })
      .catch(() => undefined);
    sbomUploads.inc({ format, status: 'error' });
  }
}
