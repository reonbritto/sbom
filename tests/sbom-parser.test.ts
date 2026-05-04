import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseSbom, SbomParseError } from '@/lib/sbom-parser';

const dataDir = join(__dirname, '..', 'data');

describe('parseSbom', () => {
  it('parses sample CycloneDX', () => {
    const buf = readFileSync(join(dataDir, 'sample-cyclonedx.json'));
    const sbom = parseSbom(buf, 'sample-cyclonedx.json');
    expect(sbom.format).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.5');
    expect(sbom.components.length).toBe(4);
    const django = sbom.components.find((c) => c.name === 'django')!;
    expect(django.ecosystem).toBe('PyPI');
    expect(django.version).toBe('2.2.0');
    expect(django.licenses).toContain('BSD-3-Clause');
    const log4j = sbom.components.find((c) => c.name === 'log4j-core')!;
    expect(log4j.ecosystem).toBe('Maven');
  });

  it('parses sample SPDX', () => {
    const buf = readFileSync(join(dataDir, 'sample-spdx.json'));
    const sbom = parseSbom(buf, 'sample-spdx.json');
    expect(sbom.format).toBe('SPDX');
    expect(sbom.specVersion).toBe('SPDX-2.3');
    expect(sbom.components.length).toBe(2);
    const lodash = sbom.components.find((c) => c.name === 'lodash')!;
    expect(lodash.ecosystem).toBe('npm');
    expect(lodash.version).toBe('4.17.15');
  });

  it('throws on invalid JSON', () => {
    expect(() => parseSbom(Buffer.from('not json'), 'x.json')).toThrow(SbomParseError);
  });

  it('throws on unknown format', () => {
    expect(() => parseSbom(Buffer.from('{"foo": 1}'), 'x.json')).toThrow(SbomParseError);
  });
});
