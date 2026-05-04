const PURL_TYPE_TO_OSV: Record<string, string> = {
  pypi: 'PyPI',
  npm: 'npm',
  maven: 'Maven',
  golang: 'Go',
  gem: 'RubyGems',
  nuget: 'NuGet',
  cargo: 'crates.io',
  composer: 'Packagist',
  conan: 'ConanCenter',
  hex: 'Hex',
  pub: 'Pub',
  swift: 'SwiftURL',
  generic: '',
};

export interface ParsedPurl {
  type: string;
  namespace: string | null;
  name: string;
  version: string | null;
  ecosystem: string | null;
}

export function parsePurl(purl: string): ParsedPurl | null {
  if (!purl.startsWith('pkg:')) return null;
  const body = purl.slice(4).split('?')[0].split('#')[0];
  const slashIdx = body.indexOf('/');
  if (slashIdx === -1) return null;
  const type = body.slice(0, slashIdx).toLowerCase();
  const rest = body.slice(slashIdx + 1);

  const atIdx = rest.lastIndexOf('@');
  const nameWithNs = atIdx === -1 ? rest : rest.slice(0, atIdx);
  const version = atIdx === -1 ? null : decodeURIComponent(rest.slice(atIdx + 1));

  const lastSlash = nameWithNs.lastIndexOf('/');
  const namespace = lastSlash === -1 ? null : decodeURIComponent(nameWithNs.slice(0, lastSlash));
  const name = decodeURIComponent(lastSlash === -1 ? nameWithNs : nameWithNs.slice(lastSlash + 1));

  return { type, namespace, name, version, ecosystem: purlTypeToEcosystem(type) };
}

export function purlTypeToEcosystem(type: string): string | null {
  const eco = PURL_TYPE_TO_OSV[type.toLowerCase()];
  if (eco === undefined) return null;
  if (eco === '') return null;
  return eco;
}

export function osvPackageName(parsed: ParsedPurl): string {
  if (parsed.type === 'maven' && parsed.namespace) return `${parsed.namespace}:${parsed.name}`;
  if (parsed.type === 'golang' && parsed.namespace) return `${parsed.namespace}/${parsed.name}`;
  if (parsed.type === 'npm' && parsed.namespace) return `${parsed.namespace}/${parsed.name}`;
  if (parsed.type === 'composer' && parsed.namespace) return `${parsed.namespace}/${parsed.name}`;
  return parsed.name;
}
