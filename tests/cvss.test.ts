import { describe, expect, it } from 'vitest';
import { parseCvssVector } from '@/lib/cvss';
import { extractCvssScore, bucketByCvss } from '@/lib/analytics';

describe('parseCvssVector', () => {
  it('parses CVSS v3.1 high-severity Log4Shell vector', () => {
    const v = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
    expect(parseCvssVector(v)).toBeCloseTo(10.0, 1);
  });
  it('parses CVSS v3 medium-severity vector', () => {
    const v = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N';
    const score = parseCvssVector(v)!;
    expect(score).toBeGreaterThan(4);
    expect(score).toBeLessThan(7);
  });
  it('parses CVSS v2 vector', () => {
    expect(parseCvssVector('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeCloseTo(7.5, 0);
  });
  it('handles bare numeric score', () => {
    expect(parseCvssVector('9.8')).toBe(9.8);
  });
  it('returns null on garbage', () => {
    expect(parseCvssVector('')).toBeNull();
    expect(parseCvssVector('not-a-vector')).toBeNull();
  });
});

describe('extractCvssScore + bucketByCvss', () => {
  it('flows real OSV vectors into severity buckets', () => {
    const vuln = {
      id: 'GHSA-test',
      severity: [
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
      ],
    };
    const { score } = extractCvssScore(vuln as never);
    expect(bucketByCvss(score)).toBe('CRITICAL');
  });
  it('falls back to database_specific severity label', () => {
    const vuln = {
      id: 'GHSA-x',
      severity: [],
      database_specific: { severity: 'HIGH' },
    };
    const { score } = extractCvssScore(vuln as never);
    expect(bucketByCvss(score)).toBe('HIGH');
  });
});
