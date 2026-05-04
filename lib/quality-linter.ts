export type QualitySeverity = 'critical' | 'high' | 'medium' | 'low';

export interface QualityIssue {
  id: string;
  rule: string;
  category: 'NTIA' | 'BSI-TR' | 'CRA' | 'Hygiene';
  severity: QualitySeverity;
  count: number;
  title: string;
  detail: string;
  learnMoreUrl?: string;
}

interface CycloneDxComponent {
  name?: string;
  version?: string;
  purl?: string;
  supplier?: { name?: string };
  bomRef?: string;
  hashes?: { alg: string; content: string }[];
  licenses?: unknown[];
}

interface CycloneDxRoot {
  bomFormat?: string;
  specVersion?: string;
  metadata?: {
    timestamp?: string;
    authors?: { name?: string }[];
    supplier?: { name?: string };
    component?: { name?: string; version?: string };
  };
  components?: CycloneDxComponent[];
  dependencies?: { ref: string; dependsOn?: string[] }[];
}

interface SpdxRoot {
  spdxVersion?: string;
  creationInfo?: { created?: string; creators?: string[] };
  packages?: {
    name?: string;
    versionInfo?: string;
    SPDXID?: string;
    supplier?: string;
    originator?: string;
    externalRefs?: { referenceType?: string; referenceLocator?: string }[];
    checksums?: { algorithm: string; checksumValue: string }[];
  }[];
  relationships?: { spdxElementId: string; relatedSpdxElement: string; relationshipType: string }[];
}

export function lintSbom(raw: unknown): QualityIssue[] {
  if (!raw || typeof raw !== 'object') return [];
  const obj = raw as Record<string, unknown>;
  if (obj.bomFormat === 'CycloneDX') return lintCycloneDx(obj as CycloneDxRoot);
  if (typeof obj.spdxVersion === 'string') return lintSpdx(obj as SpdxRoot);
  return [];
}

function lintCycloneDx(sbom: CycloneDxRoot): QualityIssue[] {
  const issues: QualityIssue[] = [];
  const components = sbom.components ?? [];

  // NTIA Minimum Elements
  if (!sbom.metadata?.supplier?.name) {
    issues.push({
      id: 'ntia-supplier',
      rule: 'metadata.supplier missing',
      category: 'NTIA',
      severity: 'medium',
      count: 1,
      title: 'NTIA Minimum Elements: supplier name missing',
      detail: '(CycloneDX) metadata.supplier is missing — NTIA requires a Supplier Name for the SBOM author.',
      learnMoreUrl: 'https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf',
    });
  }

  if (!sbom.dependencies || sbom.dependencies.length === 0) {
    issues.push({
      id: 'ntia-deps',
      rule: 'dependency relationships missing',
      category: 'NTIA',
      severity: 'medium',
      count: 1,
      title: 'NTIA Minimum Elements: dependency relationships missing',
      detail: '(CycloneDX) dependency relationships are missing — NTIA requires dependency graph data so consumers can reason about transitive risk.',
      learnMoreUrl: 'https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf',
    });
  }

  if (!sbom.metadata?.authors || sbom.metadata.authors.length === 0) {
    issues.push({
      id: 'ntia-author',
      rule: 'metadata.authors missing',
      category: 'NTIA',
      severity: 'low',
      count: 1,
      title: 'NTIA Minimum Elements: SBOM author missing',
      detail: '(CycloneDX) metadata.authors is missing — NTIA requires identification of the SBOM Author.',
    });
  }

  if (!sbom.metadata?.timestamp) {
    issues.push({
      id: 'ntia-timestamp',
      rule: 'metadata.timestamp missing',
      category: 'NTIA',
      severity: 'low',
      count: 1,
      title: 'NTIA Minimum Elements: timestamp missing',
      detail: '(CycloneDX) metadata.timestamp is missing — NTIA requires a creation timestamp.',
    });
  }

  // Per-component checks
  let missingPurl = 0;
  let missingVersion = 0;
  let missingSupplier = 0;
  let missingHashes = 0;
  let missingLicenses = 0;
  for (const c of components) {
    if (!c.purl) missingPurl++;
    if (!c.version) missingVersion++;
    if (!c.supplier?.name) missingSupplier++;
    if (!c.hashes || c.hashes.length === 0) missingHashes++;
    if (!c.licenses || (Array.isArray(c.licenses) && c.licenses.length === 0)) missingLicenses++;
  }

  if (missingPurl > 0) {
    issues.push({
      id: 'ntia-purl',
      rule: 'component purl missing',
      category: 'NTIA',
      severity: 'high',
      count: missingPurl,
      title: 'NTIA Minimum Elements: unique identifier missing',
      detail: `${missingPurl} component${missingPurl === 1 ? '' : 's'} lack a Package URL (purl) — NTIA requires a unique component identifier so vulnerabilities can be matched.`,
    });
  }
  if (missingVersion > 0) {
    issues.push({
      id: 'ntia-version',
      rule: 'component version missing',
      category: 'NTIA',
      severity: 'high',
      count: missingVersion,
      title: 'NTIA Minimum Elements: component version missing',
      detail: `${missingVersion} component${missingVersion === 1 ? '' : 's'} have no version — vulnerability matching is impossible without a version.`,
    });
  }
  if (missingSupplier > 0) {
    issues.push({
      id: 'ntia-component-supplier',
      rule: 'component supplier missing',
      category: 'NTIA',
      severity: 'medium',
      count: missingSupplier,
      title: 'NTIA Minimum Elements: component supplier missing',
      detail: `${missingSupplier} component${missingSupplier === 1 ? '' : 's'} lack supplier info — NTIA requires Supplier Name for each component.`,
    });
  }
  if (missingHashes > 0) {
    issues.push({
      id: 'hygiene-hashes',
      rule: 'component hash missing',
      category: 'Hygiene',
      severity: 'low',
      count: missingHashes,
      title: 'Component integrity hash missing',
      detail: `${missingHashes} component${missingHashes === 1 ? '' : 's'} have no checksum — hashes let downstream consumers verify the artifact.`,
    });
  }
  if (missingLicenses > 0) {
    issues.push({
      id: 'hygiene-licenses',
      rule: 'component license missing',
      category: 'Hygiene',
      severity: 'medium',
      count: missingLicenses,
      title: 'License information missing',
      detail: `${missingLicenses} component${missingLicenses === 1 ? '' : 's'} lack license metadata — required for compliance review.`,
    });
  }

  if (!sbom.metadata?.component?.name) {
    issues.push({
      id: 'cra-root',
      rule: 'root component undefined',
      category: 'CRA',
      severity: 'low',
      count: 1,
      title: 'Root component (subject of SBOM) not declared',
      detail: '(CycloneDX) metadata.component is missing — the SBOM does not declare what product it describes.',
    });
  }

  return issues;
}

function lintSpdx(sbom: SpdxRoot): QualityIssue[] {
  const issues: QualityIssue[] = [];
  const packages = sbom.packages ?? [];

  if (!sbom.creationInfo?.creators || sbom.creationInfo.creators.length === 0) {
    issues.push({
      id: 'ntia-author', rule: 'creators missing', category: 'NTIA', severity: 'low', count: 1,
      title: 'NTIA Minimum Elements: SBOM author missing',
      detail: '(SPDX) creationInfo.creators is missing — NTIA requires SBOM Author identification.',
    });
  }
  if (!sbom.creationInfo?.created) {
    issues.push({
      id: 'ntia-timestamp', rule: 'created missing', category: 'NTIA', severity: 'low', count: 1,
      title: 'NTIA Minimum Elements: timestamp missing',
      detail: '(SPDX) creationInfo.created is missing — NTIA requires a creation timestamp.',
    });
  }
  if (!sbom.relationships || sbom.relationships.length === 0) {
    issues.push({
      id: 'ntia-deps', rule: 'relationships missing', category: 'NTIA', severity: 'medium', count: 1,
      title: 'NTIA Minimum Elements: dependency relationships missing',
      detail: '(SPDX) relationships array is missing — NTIA requires dependency graph data.',
    });
  }

  let missingPurl = 0;
  let missingVersion = 0;
  let missingSupplier = 0;
  let missingHashes = 0;
  for (const p of packages) {
    if (!p.externalRefs?.some((r) => r.referenceType === 'purl')) missingPurl++;
    if (!p.versionInfo || p.versionInfo === 'NOASSERTION') missingVersion++;
    if (!p.supplier && !p.originator) missingSupplier++;
    if (!p.checksums || p.checksums.length === 0) missingHashes++;
  }

  if (missingPurl > 0) {
    issues.push({
      id: 'ntia-purl', rule: 'package purl missing', category: 'NTIA', severity: 'high', count: missingPurl,
      title: 'NTIA Minimum Elements: unique identifier missing',
      detail: `${missingPurl} package${missingPurl === 1 ? '' : 's'} lack a Package URL externalRef.`,
    });
  }
  if (missingVersion > 0) {
    issues.push({
      id: 'ntia-version', rule: 'versionInfo missing', category: 'NTIA', severity: 'high', count: missingVersion,
      title: 'NTIA Minimum Elements: component version missing',
      detail: `${missingVersion} package${missingVersion === 1 ? '' : 's'} have NOASSERTION or missing versionInfo.`,
    });
  }
  if (missingSupplier > 0) {
    issues.push({
      id: 'ntia-component-supplier', rule: 'supplier missing', category: 'NTIA', severity: 'medium', count: missingSupplier,
      title: 'NTIA Minimum Elements: component supplier missing',
      detail: `${missingSupplier} package${missingSupplier === 1 ? '' : 's'} have no supplier or originator.`,
    });
  }
  if (missingHashes > 0) {
    issues.push({
      id: 'hygiene-hashes', rule: 'checksum missing', category: 'Hygiene', severity: 'low', count: missingHashes,
      title: 'Component integrity hash missing',
      detail: `${missingHashes} package${missingHashes === 1 ? '' : 's'} have no checksum.`,
    });
  }

  return issues;
}

export function summarizeIssues(issues: QualityIssue[]) {
  const byBand = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const i of issues) byBand[i.severity] += 1;
  return { byBand, total: issues.length };
}
