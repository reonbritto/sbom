# SBOM Vulnerability Analyzer

Upload a CycloneDX or SPDX Software Bill of Materials. See every known vulnerability affecting your components — enriched with real-world exploit probability, active-exploitation flags, attacker techniques, and one-click fix suggestions.

[![CI](https://github.com/reonbritto/sbom/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/reonbritto/sbom/actions/workflows/ci.yml)
[![Release](https://github.com/reonbritto/sbom/actions/workflows/release-please.yml/badge.svg?branch=main)](https://github.com/reonbritto/sbom/actions/workflows/release-please.yml)
[![DockerHub](https://img.shields.io/docker/v/reonbritto/sbom-vuln-analyzer/latest?logo=docker&label=DockerHub)](https://hub.docker.com/r/reonbritto/sbom-vuln-analyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

You give it an SBOM. It tells you what's actually dangerous.

| Capability | What you see | Source |
|---|---|---|
| **Component vulnerability lookup** | Every CVE per package version | [OSV.dev](https://osv.dev) |
| **EPSS exploit probability** | "This 6.5 has 91% exploit chance — patch first; that 9.8 has 0.04% — defer" | [FIRST.org](https://www.first.org/epss) |
| **CISA KEV active-exploitation flag** | Red banner + federal patch deadline for CVEs being exploited in the wild | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **CVE / CWE / NVD detail** | Full advisory with weakness classification | NVD API |
| **MITRE ATT&CK mapping** | "If exploited, what does the attacker do?" — tactics + techniques | Curated CWE → ATT&CK |
| **Package reputation** | Popularity, OpenSSF Scorecard score, malicious flag | [deps.dev](https://deps.dev) |
| **Typosquat / supply-chain detection** | Catches `event-stream`-style attacks (typo'd lookalikes, suspicious newcomers) | Reputation-aware heuristics |
| **Composite risk score** | One number per component (0–100), with rationale | CVSS + EPSS + KEV + reputation |
| **One-version fix planner** | The single upgrade that resolves the most CVEs at once | OSV affected-version ranges |
| **NTIA Minimum Elements lint** | Surfaces missing supplier, version, dependency relationships in the SBOM itself | CycloneDX/SPDX schema |
| **Reports** | JSON · CycloneDX VEX · printable HTML | Built-in exporters |

---

## Demo

After signing up, click **Load demo SBOM**. The bundled demo includes:

- `log4j-core@2.14.1` — Log4Shell, CVSS 10, in CISA KEV
- `requests@2.30.0` — Python HTTP library with known CVEs
- `lodash@4.17.20` — classic prototype-pollution era
- `xml2js@0.4.23` — prototype pollution again
- `event-stream-typo` — fake typosquat to demo the supply-chain detector
- a few clean components for contrast

You'll see risk scores, KEV banners, ATT&CK mappings, EPSS percentiles, and recommended fixes within ~10 seconds.

---

## Quick start

```sh
git clone https://github.com/reonbritto/sbom
cd sbom
cp .env.example .env
docker compose up --build
```

Open http://localhost:3000 — sign up, then click **Load demo SBOM**.

The full stack runs in docker-compose: Postgres for storage, Redis for caching enriched vulnerability data, plus Prometheus + Grafana + Loki for local observability.

### Configuration

The defaults work out of the box. To tune behaviour, edit `.env`:

| Variable | Default | Purpose |
|---|---|---|
| `MAX_SBOM_BYTES` | `10485760` (10 MB) | File-size cap on uploads |
| `MAX_COMPONENTS` | `10000` | Component cap per SBOM |
| `OSV_CONCURRENCY` | `10` | Parallel OSV.dev lookups |
| `CACHE_TTL_SECONDS` | `3600` | Redis cache TTL for component lookups |
| `VULN_CACHE_TTL_SECONDS` | `86400` | Cache TTL for full vulnerability records |

---

## How it works

```
   ┌─────────────────────────┐
   │  CycloneDX or SPDX JSON │
   └────────────┬────────────┘
                ▼
   ┌──────────────────────────────────────────────┐
   │  Parse → extract purl + version per component│
   └────────────┬─────────────────────────────────┘
                ▼
   ┌──────────────────────────────────────────────┐
   │  Enrichment pipeline (parallel, cached)      │
   │  ├─ OSV.dev      → CVEs + advisory metadata  │
   │  ├─ FIRST EPSS   → exploit probability       │
   │  ├─ CISA KEV     → active-exploitation flag  │
   │  ├─ NVD          → full CVE + CWE detail     │
   │  └─ deps.dev     → Scorecard + reputation    │
   └────────────┬─────────────────────────────────┘
                ▼
   ┌──────────────────────────────────────────────┐
   │  Score + plan                                │
   │  ├─ Composite risk score (CVSS · EPSS · KEV) │
   │  ├─ Typosquat / supply-chain detector        │
   │  ├─ MITRE ATT&CK technique mapping           │
   │  └─ One-version fix recommendation           │
   └────────────┬─────────────────────────────────┘
                ▼
   ┌──────────────────────────────────────────────┐
   │  UI · API · Reports (JSON · VEX · HTML)      │
   └──────────────────────────────────────────────┘
```

All external API responses are cached in Redis (1 h for OSV component queries, 24 h for full vuln records, 24 h for KEV catalog) so re-uploading the same SBOM is near-instant.

---

## Built with

- **Next.js 15** (App Router) + React 19 + Tailwind + shadcn/ui + Recharts
- **Better Auth** — self-hosted email/password, Argon2id-hashed, sessions in Postgres
- **Prisma** + **Postgres 16** for persistence
- **Redis 7** for the enrichment cache
- **prom-client** for `/api/metrics`

---

## License

[MIT](LICENSE)
