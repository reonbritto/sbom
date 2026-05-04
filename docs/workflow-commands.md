# Workflow Commands

Day-to-day commands for working in this repo.

---

## Daily flow — feature → PR → merge

```sh
# 1. Sync local main
git checkout main
git pull

# 2. Create a feature branch (Conventional Commits prefix)
git checkout -b feat/sbom-diff
# or:  fix/auth-bug   chore/deps   docs/runbook   refactor/scan-pipeline   security/cve-bump

# 3. Work, then stage + commit
git status
git add <files>
git commit -m "feat(scan): add SBOM diff endpoint"

# 4. Push the branch
git push -u origin feat/sbom-diff

# 5. Open the PR
gh pr create --fill                                       # uses last commit msg as title/body
# or with explicit fields:
gh pr create \
  --title "feat(scan): add SBOM diff endpoint" \
  --body "## What\n...\n\n## Why\n..."

# 6. Watch CI
gh pr checks --watch                                      # live tail of all checks
gh pr view --web                                          # open PR in browser

# 7. Once green, merge (admin bypass since we're solo)
gh pr merge <number> --squash --admin --delete-branch

# 8. Sync main again
git checkout main
git pull
git branch -D feat/sbom-diff                              # local cleanup if not auto-deleted
```

---

## Inspecting the pipeline

```sh
# Latest workflow runs
gh run list --workflow=ci.yml --limit 10

# Latest run on main
gh run list --workflow=ci.yml --branch=main --limit 1

# Watch a specific run live
gh run watch <run-id>

# Job-by-job summary of a run
gh run view <run-id>

# Per-job conclusion table
gh run view <run-id> --json jobs -q '.jobs[] | "\(.name) | \(.conclusion)"'

# Open run in browser
gh run view <run-id> --web

# Re-run failed jobs only
gh run rerun <run-id> --failed

# Re-run all jobs
gh run rerun <run-id>

# Cancel a running workflow
gh run cancel <run-id>
```

---

## Working with PRs

```sh
# List PRs
gh pr list                                                # open
gh pr list --state all --limit 20                         # everything
gh pr list --search "is:open is:pr label:security"        # filtered

# View a PR
gh pr view <number>
gh pr view <number> --json mergeable,mergeStateStatus,reviewDecision
gh pr view <number> --comments

# View live CI status of your current branch's PR
gh pr checks --watch

# Add a label
gh pr edit <number> --add-label security

# Close without merging
gh pr close <number> --delete-branch

# Reopen
gh pr reopen <number>

# Comment
gh pr comment <number> --body "looking now"

# Approve (if you're not the author)
gh pr review <number> --approve --body "LGTM"

# Request changes
gh pr review <number> --request-changes --body "see inline"
```

---

## Hotfix flow

```sh
# Cut a fix from current main, fast-track it
git checkout main && git pull
git checkout -b hotfix/cve-2026-1234
# fix
git commit -m "security(deps): patch CVE-2026-1234"
git push -u origin hotfix/cve-2026-1234
gh pr create --title "security(deps): patch CVE-2026-1234" --label hotfix
# wait for CI, admin-merge
gh pr merge <number> --squash --admin --delete-branch
```

---

## Rollback a bad merge

```sh
# Identify the bad commit
git log --oneline -10

# Create a revert PR
git checkout main && git pull
git checkout -b revert/bad-feature
git revert <bad-sha>                                      # creates a new commit that undoes it
git push -u origin revert/bad-feature
gh pr create --title "revert: bad feature (was abc1234)"
gh pr merge <number> --squash --admin --delete-branch
```

---

## Secrets management

```sh
# List secrets (names only, values are write-only)
gh secret list

# Set / update a secret
gh secret set DOCKERHUB_TOKEN -b "<value>"
gh secret set DOCKERHUB_TOKEN < token.txt                 # from file

# Delete
gh secret delete OLD_SECRET
```

---

## Branch protection / ruleset inspection

```sh
# List rulesets
gh api repos/reonbritto/sbom-analyzer/rulesets

# Show one
gh api repos/reonbritto/sbom-analyzer/rulesets/15941161

# Required check names + bypass actors
gh api repos/reonbritto/sbom-analyzer/rulesets/15941161 \
  --jq '{checks: [.rules[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context], bypass: .bypass_actors}'

# Update (PUT — full ruleset spec required)
gh api repos/reonbritto/sbom-analyzer/rulesets/15941161 --method PUT --input ruleset.json

# Delete a ruleset
gh api repos/reonbritto/sbom-analyzer/rulesets/15941161 --method DELETE
```

---

## Workflow-file maintenance

```sh
# Validate the YAML before committing
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('YAML OK')"

# List all jobs in the workflow
grep -n '^  [a-z-]*:$' .github/workflows/ci.yml

# See job dependencies + guards
grep -nE '^  [a-z-]*:$|needs:|^    if:' .github/workflows/ci.yml

# Manually trigger a workflow_dispatch workflow (if you add one)
gh workflow run ci.yml --ref main
gh workflow run tf-apply-prod.yml --ref main -f environment=prod
```

---

## DockerHub verification

```sh
# Check what tags are published
curl -s "https://hub.docker.com/v2/repositories/reonbritto/sbom-vuln-analyzer/tags/?page_size=10" \
  | python -c "import json,sys; [print(f\"{t['name']:<20} {t['last_updated']}\") for t in json.load(sys.stdin)['results']]"

# Pull and run the latest pushed image locally
docker pull reonbritto/sbom-vuln-analyzer:latest
docker run --rm -p 3000:3000 reonbritto/sbom-vuln-analyzer:latest
```

---

## Getting un-stuck

```sh
# Forgot what branch you're on
git branch --show-current

# What's different from main
git log main..HEAD --oneline                              # commits ahead of main
git diff main...HEAD --stat                               # files changed

# Pull latest main into your feature branch (rebase to keep linear history)
git fetch origin
git rebase origin/main
# fix conflicts → git add → git rebase --continue
git push --force-with-lease                               # safer than --force

# Throw away local commits and reset to origin
git reset --hard origin/main

# Clean up merged branches locally
git branch --merged main | grep -v '^\*\|main' | xargs -r git branch -d

# Prune deleted remote branches
git fetch -p
```

---

## Quick reference

```sh
# Branch / PR / CI in three commands
git checkout -b feat/X && git push -u origin feat/X        # branch + push
gh pr create --fill                                        # PR
gh pr checks --watch                                       # watch
gh pr merge <n> --squash --admin --delete-branch           # merge
```
