const V3_AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const V3_AC: Record<string, number> = { L: 0.77, H: 0.44 };
const V3_PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const V3_PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const V3_UI: Record<string, number> = { N: 0.85, R: 0.62 };
const V3_CIA: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

const V2_AV: Record<string, number> = { L: 0.395, A: 0.646, N: 1.0 };
const V2_AC: Record<string, number> = { H: 0.35, M: 0.61, L: 0.71 };
const V2_AU: Record<string, number> = { M: 0.45, S: 0.56, N: 0.704 };
const V2_CIA: Record<string, number> = { N: 0, P: 0.275, C: 0.66 };

export function parseCvssVector(vector: string): number | null {
  if (!vector || typeof vector !== 'string') return null;
  const trimmed = vector.trim();
  const numericOnly = parseFloat(trimmed);
  if (!isNaN(numericOnly) && !trimmed.includes('/')) return clamp(numericOnly);

  if (trimmed.startsWith('CVSS:3')) return scoreV3(trimmed);
  if (trimmed.startsWith('AV:') || trimmed.startsWith('(AV:')) return scoreV2(trimmed);
  return null;
}

function fields(vector: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of vector.replace(/^\(|\)$/g, '').split('/')) {
    const [k, v] = part.split(':');
    if (k && v) out[k.trim()] = v.trim();
  }
  return out;
}

function scoreV3(vector: string): number | null {
  const f = fields(vector);
  const av = V3_AV[f.AV];
  const ac = V3_AC[f.AC];
  const ui = V3_UI[f.UI];
  const c = V3_CIA[f.C];
  const i = V3_CIA[f.I];
  const a = V3_CIA[f.A];
  const scope = f.S;
  if (av === undefined || ac === undefined || ui === undefined || c === undefined || i === undefined || a === undefined || !scope) return null;
  const prTable = scope === 'C' ? V3_PR_C : V3_PR_U;
  const pr = prTable[f.PR];
  if (pr === undefined) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scope === 'C'
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const base = scope === 'C'
    ? roundUp(Math.min(1.08 * (impact + exploitability), 10))
    : roundUp(Math.min(impact + exploitability, 10));
  return base;
}

function scoreV2(vector: string): number | null {
  const f = fields(vector);
  const av = V2_AV[f.AV];
  const ac = V2_AC[f.AC];
  const au = V2_AU[f.Au] ?? V2_AU[f.AU];
  const c = V2_CIA[f.C];
  const i = V2_CIA[f.I];
  const a = V2_CIA[f.A];
  if ([av, ac, au, c, i, a].some((x) => x === undefined)) return null;
  const impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a));
  const exploitability = 20 * av * ac * au;
  const fImpact = impact === 0 ? 0 : 1.176;
  const base = (0.6 * impact + 0.4 * exploitability - 1.5) * fImpact;
  return roundOne(Math.max(0, Math.min(10, base)));
}

function roundUp(value: number): number {
  return Math.ceil(value * 10) / 10;
}
function roundOne(value: number): number {
  return Math.round(value * 10) / 10;
}
function clamp(value: number): number {
  return Math.max(0, Math.min(10, value));
}
