# SBOM Vulnerability Analyzer

Upload a CycloneDX or SPDX SBOM, get every known vulnerability affecting its components — enriched with EPSS exploit probability, CISA KEV flags, OpenSSF Scorecard, NVD CWE/CVE detail, MITRE ATT&CK mapping, and recommended fix versions.

[![CI](https://github.com/reon/sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/reon/sbom/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

| Capability | Source | Why it matters |
|---|---|---|
| Component vuln lookup | OSV.dev | Per-package vulnerability resolution from purl + version |
| Exploit probability | FIRST.org EPSS | "Patch the 6.5 with 91% chance, not the 9.8 with 0.04%" |
| Active exploitation flag | CISA KEV catalog (bulk-cached) | Federal patch deadlines for CVEs known to be exploited |
| CWE classification + ATT&CK mapping | NVD + curated CWE→ATT&CK table | "If exploited, what does the attacker do?" |
| Package reputation | deps.dev (Google) | OpenSSF Scorecard, popularity, malicious flag |
| Typosquat / supply-chain detection | Reputation-aware heuristics | Catches event-stream / ua-parser-js style attacks |
| Composite risk score | CVSS + EPSS + KEV + reputation | One number per component, with rationale |
| One-version fix planner | OSV ranges | The single upgrade that fixes the most CVEs |
| NTIA quality lint | CycloneDX/SPDX schema check | Surfaces missing supplier, missing dep relationships |
| Reports | JSON / CycloneDX VEX / printable HTML | Hand to auditors / Dependency-Track / customers |

---

## Stack

- **Next.js 15** (App Router) + React 19 + Tailwind 4 + shadcn/ui + Recharts
- **Better Auth** (self-hosted email/password, Argon2id, sessions in Postgres)
- **Prisma** + **Postgres 16**
- **ioredis** + **Redis 7** (TTL cache for OSV/EPSS/NVD/deps.dev/KEV)
- **prom-client** for `/api/metrics`
- **Docker / docker-compose** for local

---

## Quick start

```sh
cp .env.example .env
docker compose up --build
```

Open http://localhost:3000 — sign up, click **Load demo SBOM**.

---

## Repo layout

```
.
├── app/              Next.js routes (App Router)
├── components/       shadcn UI + bespoke (RiskBadge, KevBadge, EpssBadge, …)
├── lib/              domain logic (osv-client, epss-client, kev-catalog, scan, risk-score, …)
├── prisma/           schema (Better Auth + Analysis/Component/Vuln tables)
├── data/             sample SBOMs (incl. Log4Shell demo)
├── tests/            vitest
├── monitoring/       prometheus / grafana / loki / promtail configs (local docker-compose)
└── .github/          CI workflows + governance
```

GitOps manifests (Kustomize, Argo Apps) live in [`reon/sbom-platform`](https://github.com/reon/sbom-platform).

---

## Development

```sh
npm install --legacy-peer-deps
npm run dev          # next dev on :3000
npm run test         # vitest
npm run lint         # next lint
npm run typecheck    # tsc --noEmit
```

### Branching

Trunk-based. Short-lived `feat/`, `fix/`, `chore/` branches → squash-merge to `main`. Releases will eventually be annotated tags `vX.Y.Z`.

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/) — enforced by [.github/workflows/lint-pr.yml](.github/workflows/lint-pr.yml).

```
feat(scan): add SBOM diff endpoint
fix(auth): handle expired session cookie
security(deps): bump next to 15.2.4
```

---

## CI

| Workflow | Trigger | What it does |
|---|---|---|
| [ci.yml](.github/workflows/ci.yml) | push, PR | lint → typecheck/build → test → CodeQL SAST → Snyk SCA → Gitleaks → npm audit → CycloneDX SBOM → Trivy fs → Docker build → Trivy image scan → Docker push (main only) |
| [lint-pr.yml](.github/workflows/lint-pr.yml) | PR open | Conventional Commits check on PR title |

### Required GitHub repo secrets

| Secret | Purpose |
|---|---|
| `SNYK_TOKEN` | Snyk SCA SARIF upload to GitHub Security tab |
| `DOCKERHUB_USERNAME` | DockerHub login + image namespace |
| `DOCKERHUB_TOKEN` | DockerHub access token (Account → Security → New Access Token) |

ACR push, Cosign signing, Harness webhook, GitOps trigger, Terraform plan/apply will be added later — currently deferred.

---

## License

[MIT](LICENSE)
