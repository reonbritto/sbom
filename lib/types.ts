export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

export type SbomFormat = 'CycloneDX' | 'SPDX';

export type AnalysisStatus = 'PARSING' | 'SCANNING' | 'COMPLETE' | 'ERROR';

export interface ParsedComponent {
  purl: string;
  name: string;
  version: string;
  ecosystem: string | null;
  licenses: string[];
}

export interface ParsedSbom {
  format: SbomFormat;
  specVersion: string;
  components: ParsedComponent[];
}

export interface OsvVulnRef {
  id: string;
  modified?: string;
}

export interface OsvBatchResult {
  results: { vulns?: OsvVulnRef[] }[];
}

export interface OsvSeverity {
  type: string;
  score: string;
}

export interface OsvAffectedRange {
  type: string;
  events: { introduced?: string; fixed?: string; last_affected?: string }[];
}

export interface OsvAffected {
  package: { name: string; ecosystem: string; purl?: string };
  ranges?: OsvAffectedRange[];
  versions?: string[];
}

export interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
  references?: { type: string; url: string }[];
  affected?: OsvAffected[];
  published?: string;
  modified?: string;
}

export interface ComponentVulnSummary {
  id: string;
  severity: Severity;
  cvssScore: number | null;
  summary: string;
}

export interface SeverityDistribution {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  NONE: number;
}
