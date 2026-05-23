# Running locally

End-to-end steps to bring the stack up on your laptop with Docker Compose, plus the URLs to hit once it's running.

---

## 1. Prereqs

- Docker Desktop (or Docker Engine + Compose v2) — `docker compose version` must be ≥ v2.20
- Free ports on localhost: **3000, 3001, 6379, 9090, 3100, 54433**
- ~2 GB free RAM

That's it. No Node, npm, Postgres, or Redis on the host — everything runs in containers.

---

## 2. Configure

```sh
git clone https://github.com/reonbritto/sbom-analyzer
cd sbom-analyzer
cp .env.example .env
```

Open `.env` and set **one** required value:

```sh
BETTER_AUTH_SECRET=...      # generate via: openssl rand -hex 32
```

Defaults for everything else (`DATABASE_URL`, `REDIS_URL`, cache TTLs, upload caps) work out of the box.

---

## 3. Start

```sh
docker compose up --build
```

First run takes ~2–3 minutes (downloads images, builds the web image, runs Prisma migrations). Subsequent runs are seconds.

To run in the background:

```sh
docker compose up -d --build
```

Check status:

```sh
docker compose ps
# All services should be Up (postgres + redis show "(healthy)")
```

---

## 4. Open the app

| Service | URL | Login |
|---|---|---|
| **SBOM Analyzer** (main app) | http://localhost:3000 | sign up with any email + 8+ char password |
| Grafana | http://localhost:3001 | `admin` / `admin` (prompts to change on first login) |
| Prometheus | http://localhost:9090 | none |
| Loki API | http://localhost:3100/ready | none (no UI; query via Grafana) |

Internal services (no UI — for direct DB/cache access from your host):

| Service | Host port | Container port |
|---|---|---|
| Postgres | `localhost:54433` | 5432 (in container) |
| Redis | `localhost:6379` | 6379 |

---

## 5. Demo flow

1. Open http://localhost:3000
2. Click **Sign up**, enter any email + password
3. After login, click **Load demo SBOM**
4. Wait ~10 seconds for the analysis to finish
5. You'll see:
   - 4 components with real CVEs (Log4Shell, lodash prototype pollution, etc.)
   - 1 fake typosquat detected by the supply-chain heuristics
   - Composite risk scores, EPSS percentiles, KEV banners, MITRE ATT&CK mappings, one-version fix recommendations

---

## 6. Observe what the app is doing

### App metrics (Prometheus)

The app exposes `/api/metrics` — scraped every 15s by the Prometheus container.

Open http://localhost:9090 and try:

```promql
# Request rate per endpoint
rate(http_requests_total[1m])

# SBOM upload count
sbom_uploads_total

# OSV.dev cache hit ratio
rate(osv_cache_hits_total[5m]) / rate(osv_lookups_total[5m])

# In-flight enrichment jobs
sbom_analysis_in_progress
```

### App logs (Grafana → Loki)

Promtail tails container logs and ships them to Loki. Grafana has Loki pre-wired as a datasource.

1. Open http://localhost:3001
2. Login `admin` / `admin` (set a new password)
3. **Explore** → datasource **Loki**
4. Try these queries:

```logql
# All logs from the web container
{container="sbom-web-1"}

# Just errors
{container="sbom-web-1"} |= "error"

# Better Auth events
{container="sbom-web-1"} |= "Better Auth"

# Postgres queries (Prisma logs)
{container="sbom-web-1"} |= "prisma"
```

### Dashboards (Grafana)

No pre-built dashboards ship with this repo. To build one:

1. Grafana → **Dashboards** → **New** → **Add visualization**
2. Pick **Prometheus** datasource
3. Paste one of the PromQL queries from above
4. Save the dashboard JSON to `monitoring/grafana/dashboards/` if you want it version-controlled (then mount the dir in `docker-compose.yml`)

---

## 7. Common tasks

### Tail logs from the host (alternative to Loki)

```sh
docker compose logs -f web        # app logs
docker compose logs -f postgres   # DB
docker compose logs -f --tail=50  # everything, last 50 lines each
```

### Connect to Postgres

```sh
docker compose exec postgres psql -U sbom -d sbom
# Or from your host:
psql "postgresql://sbom:sbom@localhost:54433/sbom"
```

### Connect to Redis

```sh
docker compose exec redis redis-cli
# Or from host:
redis-cli -p 6379
```

### Wipe everything and start fresh

```sh
docker compose down -v          # -v also drops the named volumes (DB + Grafana data)
docker compose up --build
```

### Pick up code changes

The `web` container is built from this repo; it doesn't hot-reload. After editing app code:

```sh
docker compose up -d --build web
```

(`-d` keeps it in the background; `--build web` only rebuilds the one service.)

---

## 8. Stopping

```sh
docker compose down       # stop containers, keep volumes (DB stays)
docker compose down -v    # stop AND delete volumes (clean slate next time)
```

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| "Invalid origin" on login | You're accessing via `127.0.0.1:3000` or another host. Use `http://localhost:3000` (the app trusts both `localhost` and `127.0.0.1` on port 3000 — if you customized the URL, add it to `trustedOrigins` in `lib/auth.ts`). |
| Web container exits with `EADDRINUSE :::3000` | Another process is using port 3000. `lsof -i :3000` (mac/linux) or `netstat -ano \| findstr 3000` (Windows), kill it, retry. |
| Postgres "database does not exist" on first run | The `postgres` service didn't finish initializing before the web container ran `prisma db push`. `docker compose down -v && docker compose up --build`. |
| `docker compose up` errors with `pull access denied for sbom-web` | The image hasn't been built locally yet. Use `--build` on the first run. |
| Demo SBOM analysis hangs at "Enriching" forever | OSV.dev or NVD API is rate-limiting. Check `docker compose logs web` for `429` responses. Wait a minute, retry. |
| Grafana shows "No data" everywhere | Promtail / Prometheus haven't scraped yet. Wait 30s after start. If still empty, check `docker compose logs prometheus promtail`. |
