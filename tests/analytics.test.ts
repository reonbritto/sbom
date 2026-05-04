import { describe, expect, it } from 'vitest';
import { bucketByCvss, compareSeverity, maxSeverity, summarizeVuln } from '@/lib/analytics';
import type { OsvVuln } from '@/lib/types';

describe('bucketByCvss', () => {
  it('buckets correctly', () => {
    expect(bucketByCvss(9.8)).toBe('CRITICAL');
    expect(bucketByCvss(7.5)).toBe('HIGH');
    expect(bucketByCvss(5.0)).toBe('MEDIUM');
    expect(bucketByCvss(2.0)).toBe('LOW');
    expect(bucketByCvss(0)).toBe('NONE');
    expect(bucketByCvss(null)).toBe('NONE');
  });
});

describe('maxSeverity', () => {
  it('picks the highest', () => {
    expect(maxSeverity(['LOW', 'CRITICAL', 'MEDIUM'])).toBe('CRITICAL');
    expect(maxSeverity(['NONE'])).toBe('NONE');
  });
});

describe('compareSeverity', () => {
  it('sorts critical before high', () => {
    expect(compareSeverity('CRITICAL', 'HIGH')).toBeLessThan(0);
    expect(compareSeverity('HIGH', 'CRITICAL')).toBeGreaterThan(0);
  });
});

describe('summarizeVuln', () => {
  it('extracts cvss and fixed versions', () => {
    const v: OsvVuln = {
      id: 'GHSA-xxxx',
      severity: [{ type: 'CVSS_V3', score: '9.8' }],
      affected: [
        { package: { name: 'foo', ecosystem: 'PyPI' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }] }] },
      ],
    };
    const s = summarizeVuln(v);
    expect(s.severity).toBe('CRITICAL');
    expect(s.cvssScore).toBe(9.8);
    expect(s.fixedVersions).toContain('1.2.3');
  });
});
