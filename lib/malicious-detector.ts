import type { PackageReputation } from './depsdev-client';
import { isWellEstablished } from './depsdev-client';

const POPULAR_TARGETS: Record<string, string[]> = {
  npm: [
    'react', 'lodash', 'express', 'axios', 'moment', 'webpack', 'next',
    'typescript', 'eslint', 'prettier', 'babel-core', 'vue', 'angular',
    'jquery', 'underscore', 'request', 'chalk', 'commander', 'colors',
    'debug', 'glob', 'minimist', 'fs-extra', 'dotenv', 'uuid',
    'bluebird', 'node-fetch', 'cross-env', 'rimraf', 'jest', 'mocha',
    'react-dom', 'tailwindcss', 'redux', 'graphql', 'mongoose', 'puppeteer',
    'discord.js', 'electron', 'socket.io', 'ws', 'cookie', 'cookie-parser',
  ],
  PyPI: [
    'requests', 'urllib3', 'numpy', 'pandas', 'flask', 'django',
    'pytest', 'sqlalchemy', 'pillow', 'scipy', 'matplotlib', 'tensorflow',
    'torch', 'beautifulsoup4', 'cryptography', 'pyyaml', 'click',
    'jinja2', 'six', 'setuptools', 'wheel', 'pip', 'boto3', 'celery',
    'fastapi', 'pydantic', 'httpx', 'aiohttp', 'scikit-learn',
    'transformers', 'opencv-python', 'colorama', 'discord.py',
  ],
  RubyGems: ['rails', 'rake', 'rspec', 'bundler', 'devise', 'sidekiq', 'puma'],
};

export type MaliciousReason =
  | 'osv_malicious'
  | 'depsdev_malicious'
  | 'typosquat'
  | 'suspicious_name'
  | 'unknown_package';

export interface MaliciousFinding {
  reason: MaliciousReason;
  detail: string;
  similarTo?: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface DetectionInput {
  name: string;
  ecosystem: string | null;
  reputation?: PackageReputation | null;
}

export function detectMalicious(input: DetectionInput): MaliciousFinding | null {
  const { name, ecosystem, reputation } = input;

  if (reputation?.isMalicious) {
    return {
      reason: 'depsdev_malicious',
      detail: 'Flagged in OSV malicious-packages dataset (via deps.dev).',
      confidence: 'high',
    };
  }

  if (!ecosystem) return null;
  const popular = POPULAR_TARGETS[ecosystem];
  if (!popular) return null;

  const lower = name.toLowerCase();
  if (popular.includes(lower)) return null;
  if (isWellEstablished(reputation ?? null)) return null;

  const suspect = findSimilarPopular(lower, popular);
  if (suspect) {
    const confidence = scoreSuspicion(reputation ?? null);
    if (confidence === 'low' && reputation?.found) return null;
    return {
      reason: 'typosquat',
      detail: buildTyposquatDetail(name, suspect.trusted, suspect.dist, reputation),
      similarTo: suspect.trusted,
      confidence,
    };
  }

  if (hasSuspiciousNamePattern(lower)) {
    const confidence = isWellEstablished(reputation ?? null) ? 'low' : 'medium';
    return {
      reason: 'suspicious_name',
      detail: `Package name '${name}' matches a malicious-package naming pattern.`,
      confidence,
    };
  }

  return null;
}

interface SimilarMatch {
  trusted: string;
  dist: number;
}

function findSimilarPopular(lower: string, popular: string[]): SimilarMatch | null {
  for (const trusted of popular) {
    if (lower === trusted) continue;
    const dist = levenshtein(lower, trusted);
    if (dist === 0) continue;

    const minLen = Math.min(lower.length, trusted.length);
    const lengthDiff = Math.abs(lower.length - trusted.length);

    if (homoglyphHit(lower, trusted)) return { trusted, dist };

    const isShort = trusted.length <= 6 || lower.length <= 6;
    const passes = isShort
      ? dist === 1 && lengthDiff <= 1 && minLen >= 4
      : dist <= 2 && lengthDiff <= 2;
    if (passes) return { trusted, dist };

    if (containsSuspiciousVariation(lower, trusted)) return { trusted, dist };
  }
  return null;
}

function scoreSuspicion(rep: PackageReputation | null): 'high' | 'medium' | 'low' {
  if (!rep || !rep.found) return 'medium';
  if (rep.isMalicious) return 'high';
  if ((rep.versionsCount ?? 0) <= 1) return 'high';
  if ((rep.openssfScorecard ?? 0) >= 5) return 'low';
  if ((rep.versionsCount ?? 0) >= 5) return 'low';
  return 'medium';
}

function buildTyposquatDetail(
  name: string,
  trusted: string,
  dist: number,
  rep: PackageReputation | null | undefined,
): string {
  const parts = [
    `'${name}' resembles popular package '${trusted}' (edit distance ${dist})`,
  ];
  if (rep?.found === false) parts.push('Package not found on registry');
  if (rep?.versionsCount === 1) parts.push('Has only one published version');
  if (rep?.openssfScorecard !== null && rep?.openssfScorecard !== undefined && rep.openssfScorecard < 4) {
    parts.push(`Low OpenSSF Scorecard (${rep.openssfScorecard.toFixed(1)})`);
  }
  return parts.join(' · ');
}

export function isOsvMaliciousId(id: string): boolean {
  return /^MAL-/i.test(id);
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[a.length][b.length];
}

function homoglyphHit(name: string, trusted: string): boolean {
  if (name === trusted) return false;
  const swapped = name
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/5/g, 's')
    .replace(/3/g, 'e')
    .replace(/rn/g, 'm');
  return swapped === trusted;
}

function containsSuspiciousVariation(name: string, trusted: string): boolean {
  if (name === trusted) return false;
  if (name.endsWith(`-${trusted}`) || name.startsWith(`${trusted}-`)) return false;
  if (name.includes(trusted) && name.length - trusted.length > 0 && name.length - trusted.length <= 4) {
    const suffix = name.replace(trusted, '');
    if (/^(js|py|node|util|tools?|helper|core)$/i.test(suffix)) return true;
  }
  return false;
}

function hasSuspiciousNamePattern(name: string): boolean {
  if (/^[a-z]{1,2}\d{4,}$/.test(name)) return true;
  if (/(crypto|bitcoin|wallet|seed|private[-_]?key)/i.test(name) && name.length < 20) return true;
  return false;
}
