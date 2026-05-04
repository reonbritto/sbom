import { parsePurl } from './purl-mapper';
import type { ParsedComponent, ParsedSbom, SbomFormat } from './types';

const MAX_BYTES = parseInt(process.env.MAX_SBOM_BYTES ?? '10485760', 10);
const MAX_COMPONENTS = parseInt(process.env.MAX_COMPONENTS ?? '10000', 10);

export class SbomParseError extends Error {}

interface CycloneDxLicense {
  license?: { id?: string; name?: string };
  expression?: string;
}

interface CycloneDxComponent {
  name?: string;
  version?: string;
  purl?: string;
  licenses?: CycloneDxLicense[];
}

interface SpdxExternalRef {
  referenceCategory?: string;
  referenceType?: string;
  referenceLocator?: string;
}

interface SpdxPackage {
  name?: string;
  versionInfo?: string;
  licenseDeclared?: string;
  licenseConcluded?: string;
  externalRefs?: SpdxExternalRef[];
}

export function parseSbom(buffer: Buffer, filename: string): ParsedSbom {
  if (buffer.byteLength > MAX_BYTES) {
    throw new SbomParseError(`SBOM file exceeds max size of ${MAX_BYTES} bytes`);
  }
  let json: unknown;
  try {
    json = JSON.parse(buffer.toString('utf8'));
  } catch (err) {
    throw new SbomParseError(`Invalid JSON in ${filename}: ${(err as Error).message}`);
  }
  if (!json || typeof json !== 'object') {
    throw new SbomParseError('SBOM root must be a JSON object');
  }
  const obj = json as Record<string, unknown>;

  if (obj.bomFormat === 'CycloneDX') {
    return parseCycloneDx(obj);
  }
  if (typeof obj.spdxVersion === 'string') {
    return parseSpdx(obj);
  }
  throw new SbomParseError('Unrecognized SBOM format (expected CycloneDX or SPDX JSON)');
}

function parseCycloneDx(obj: Record<string, unknown>): ParsedSbom {
  const specVersion = String(obj.specVersion ?? 'unknown');
  const rawComponents = Array.isArray(obj.components) ? (obj.components as CycloneDxComponent[]) : [];
  if (rawComponents.length > MAX_COMPONENTS) {
    throw new SbomParseError(`SBOM exceeds component cap of ${MAX_COMPONENTS}`);
  }
  const components = rawComponents
    .map(toComponent)
    .filter((c): c is ParsedComponent => c !== null);
  return { format: 'CycloneDX', specVersion, components };
}

function toComponent(raw: CycloneDxComponent): ParsedComponent | null {
  const name = (raw.name ?? '').trim();
  const version = (raw.version ?? '').trim();
  if (!name) return null;
  const purl = raw.purl?.trim() || `pkg:generic/${encodeURIComponent(name)}@${encodeURIComponent(version || '0')}`;
  const parsed = parsePurl(purl);
  return {
    purl,
    name: parsed?.name ?? name,
    version: parsed?.version ?? version,
    ecosystem: parsed?.ecosystem ?? null,
    licenses: extractCycloneDxLicenses(raw.licenses ?? []),
  };
}

function extractCycloneDxLicenses(licenses: CycloneDxLicense[]): string[] {
  const out: string[] = [];
  for (const l of licenses) {
    if (l.expression) out.push(l.expression);
    else if (l.license?.id) out.push(l.license.id);
    else if (l.license?.name) out.push(l.license.name);
  }
  return out;
}

function parseSpdx(obj: Record<string, unknown>): ParsedSbom {
  const specVersion = String(obj.spdxVersion ?? 'unknown');
  const rawPackages = Array.isArray(obj.packages) ? (obj.packages as SpdxPackage[]) : [];
  if (rawPackages.length > MAX_COMPONENTS) {
    throw new SbomParseError(`SBOM exceeds component cap of ${MAX_COMPONENTS}`);
  }
  const components: ParsedComponent[] = [];
  for (const pkg of rawPackages) {
    const name = (pkg.name ?? '').trim();
    const version = (pkg.versionInfo ?? '').trim();
    if (!name) continue;
    const purlRef = pkg.externalRefs?.find(
      (r) => r.referenceType === 'purl' && r.referenceLocator,
    );
    const purl =
      purlRef?.referenceLocator ??
      `pkg:generic/${encodeURIComponent(name)}@${encodeURIComponent(version || '0')}`;
    const parsed = parsePurl(purl);
    const licenseStr = pkg.licenseDeclared || pkg.licenseConcluded || '';
    const licenses =
      licenseStr && licenseStr !== 'NOASSERTION' && licenseStr !== 'NONE' ? [licenseStr] : [];
    components.push({
      purl,
      name: parsed?.name ?? name,
      version: parsed?.version ?? version,
      ecosystem: parsed?.ecosystem ?? null,
      licenses,
    });
  }
  return { format: 'SPDX', specVersion, components };
}

export function detectFormat(buffer: Buffer): SbomFormat | null {
  try {
    const obj = JSON.parse(buffer.toString('utf8')) as Record<string, unknown>;
    if (obj.bomFormat === 'CycloneDX') return 'CycloneDX';
    if (typeof obj.spdxVersion === 'string') return 'SPDX';
  } catch {
    /* ignore */
  }
  return null;
}
