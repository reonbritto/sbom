import { describe, expect, it } from 'vitest';
import { osvPackageName, parsePurl, purlTypeToEcosystem } from '@/lib/purl-mapper';

describe('parsePurl', () => {
  it('parses pypi purl', () => {
    expect(parsePurl('pkg:pypi/django@2.2.0')).toEqual({
      type: 'pypi', namespace: null, name: 'django', version: '2.2.0', ecosystem: 'PyPI',
    });
  });
  it('parses maven purl with namespace', () => {
    const p = parsePurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');
    expect(p?.namespace).toBe('org.apache.logging.log4j');
    expect(p?.name).toBe('log4j-core');
    expect(p?.ecosystem).toBe('Maven');
  });
  it('parses npm scoped purl', () => {
    const p = parsePurl('pkg:npm/%40babel/core@7.0.0');
    expect(p?.namespace).toBe('@babel');
    expect(p?.name).toBe('core');
  });
  it('returns null for invalid purl', () => {
    expect(parsePurl('not-a-purl')).toBeNull();
  });
});

describe('purlTypeToEcosystem', () => {
  it('maps known types', () => {
    expect(purlTypeToEcosystem('pypi')).toBe('PyPI');
    expect(purlTypeToEcosystem('npm')).toBe('npm');
    expect(purlTypeToEcosystem('cargo')).toBe('crates.io');
  });
  it('returns null for unknown', () => {
    expect(purlTypeToEcosystem('unknown')).toBeNull();
    expect(purlTypeToEcosystem('generic')).toBeNull();
  });
});

describe('osvPackageName', () => {
  it('joins maven coords with colon', () => {
    const p = parsePurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1')!;
    expect(osvPackageName(p)).toBe('org.apache.logging.log4j:log4j-core');
  });
  it('joins go module with slash', () => {
    const p = parsePurl('pkg:golang/github.com%2Ffoo/bar@v1.0.0')!;
    expect(osvPackageName(p)).toBe('github.com/foo/bar');
  });
});
