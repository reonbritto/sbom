# Bootstrap runbook

End-to-end procedure to take the cluster from "fresh AKS just provisioned" to "Argo CD running, managing the LGTM stack + sbom-app from `sbom-platform`."

This runbook is **mechanical**. Each step has an exact command and an exact expected result. Don't paraphrase; copy-paste.

Repos involved:
- **`sbom-analyzer`** — this repo. Contains `infra/` (Terraform) and `docs/`.
- **`sbom-platform`** — `https://github.com/reonbritto/sbom-platform`. Contains all manifests + Helm values + bootstrap scripts.

---

## Table of contents

1. [Apply Terraform](#1-apply-terraform)
2. [Wire kubectl to AKS](#2-wire-kubectl-to-aks)
3. [Capture Terraform outputs](#3-capture-terraform-outputs)
4. [Substitute placeholders in `sbom-platform`](#4-substitute-placeholders-in-sbom-platform)
5. [Run bootstrap scripts](#5-run-bootstrap-scripts)
6. [Verify](#6-verify)
7. [Rollback / teardown](#7-rollback--teardown)

---

## 1. Apply Terraform

```sh
cd sbom-analyzer/infra

# One-time
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: subscription_id, grafana_admin_password,
# alertmanager_smtp_username, alertmanager_smtp_password

# Login + select sub
az login
az account set --subscription "<your-subscription-id>"

terraform init
terraform plan -out tf.plan
terraform apply tf.plan
```

Takes ~10 minutes. AKS is the slow part.

**Expected end state:** all resources show `Creation complete` with no errors. ~25 resources total.

---

## 2. Wire kubectl to AKS

```sh
# From sbom-analyzer/infra
$(terraform output -raw kube_config_command)
# expands to: az aks get-credentials --resource-group rg-sbom --name aks-sbom --overwrite-existing

kubectl config current-context
# → aks-sbom

kubectl get nodes
# → 1 node, STATUS=Ready
```

If `kubectl` errors with an AAD prompt: `kubelogin convert-kubeconfig -l azurecli`.

---

## 3. Capture Terraform outputs

You need 9 distinct values. Run each command, copy the output to a scratchpad. **Do this once; you'll paste each value 1-3 times across `sbom-platform`.**

```sh
cd sbom-analyzer/infra

terraform output -raw tenant_id
terraform output -raw subscription_id
terraform output -raw key_vault_uri
terraform output -raw eso_managed_identity_client_id
terraform output -raw external_dns_managed_identity_client_id
terraform output -raw observability_storage_account_name
terraform output -raw observability_managed_identity_client_id
```

You'll also need two values you provide yourself:

- **`__ALERT_FROM_EMAIL__`** — the Gmail address you set in `terraform.tfvars` as `alertmanager_smtp_username`. Used in Grafana SMTP config + Alertmanager + cert-manager ACME registration.
- **`__ALERT_TO_EMAIL__`** — where alerts get delivered (probably the same gmail, or your personal address).

Drop everything into a scratch file like this for the next step:

```text
__TENANT_ID__                         = dfed6615-...
__SUBSCRIPTION_ID__                   = dfed6615-...
__KEY_VAULT_URI__                     = https://kv-sbom-dev-x4k2p.vault.azure.net/
__ESO_MI_CLIENT_ID__                  = 7d8c...
__EXTERNAL_DNS_MI_CLIENT_ID__         = 4f2a...
__OBS_STORAGE_ACCOUNT__               = stsbomobs7g3k1
__OBS_MI_CLIENT_ID__                  = 9b1c...
__ALERT_FROM_EMAIL__                  = you@gmail.com
__ALERT_TO_EMAIL__                    = you@gmail.com
```

---

## 4. Substitute placeholders in `sbom-platform`

```sh
git clone https://github.com/reonbritto/sbom-platform
cd sbom-platform
```

Now substitute. Two ways: bulk find-and-replace, or file-by-file. Bulk is faster but uses real shell command risks.

### 4a. Bulk substitute (recommended, with sed)

On macOS/Linux/WSL/Git-Bash:

```sh
# Set your captured values as shell variables first:
TENANT_ID="dfed6615-..."
SUBSCRIPTION_ID="dfed6615-..."
KEY_VAULT_URI="https://kv-sbom-dev-x4k2p.vault.azure.net/"
ESO_MI="7d8c..."
EXTDNS_MI="4f2a..."
OBS_SA="stsbomobs7g3k1"
OBS_MI="9b1c..."
ALERT_FROM="you@gmail.com"
ALERT_TO="you@gmail.com"

# Replace all placeholders across the repo.
# (-i.bak keeps backups; delete with `find . -name '*.bak' -delete` after verifying.)
find . -type f \( -name '*.yaml' -o -name '*.yml' \) -exec sed -i.bak \
  -e "s|__TENANT_ID__|$TENANT_ID|g" \
  -e "s|__SUBSCRIPTION_ID__|$SUBSCRIPTION_ID|g" \
  -e "s|__KEY_VAULT_URI__|$KEY_VAULT_URI|g" \
  -e "s|__ESO_MI_CLIENT_ID__|$ESO_MI|g" \
  -e "s|__EXTERNAL_DNS_MI_CLIENT_ID__|$EXTDNS_MI|g" \
  -e "s|__OBS_STORAGE_ACCOUNT__|$OBS_SA|g" \
  -e "s|__OBS_MI_CLIENT_ID__|$OBS_MI|g" \
  -e "s|__ALERT_FROM_EMAIL__|$ALERT_FROM|g" \
  -e "s|__ALERT_TO_EMAIL__|$ALERT_TO|g" \
  {} +

# Verify nothing was missed
grep -rn '__[A-Z_]*__' . --include='*.yaml' --include='*.yml' || echo "All placeholders replaced."
```

If the verify step prints nothing (or "All placeholders replaced."), you're good.

### 4b. File-by-file (if you want explicit control)

The full inventory of placeholder locations. Edit each file at the listed line and replace the bracketed token.

| File | Line | Token to replace | Source |
|---|---|---|---|
| `helm-values/cert-manager-values.yaml` | 27 | `__EXTERNAL_DNS_MI_CLIENT_ID__` | `terraform output -raw external_dns_managed_identity_client_id` |
| `helm-values/cert-manager-values.yaml` | 28 | `__TENANT_ID__` | `terraform output -raw tenant_id` |
| `helm-values/external-secrets-values.yaml` | 11 | `__ESO_MI_CLIENT_ID__` | `terraform output -raw eso_managed_identity_client_id` |
| `helm-values/external-secrets-values.yaml` | 12 | `__TENANT_ID__` | `terraform output -raw tenant_id` |
| `helm-values/external-dns-values.yaml` | 26 | `__TENANT_ID__` | `terraform output -raw tenant_id` |
| `helm-values/external-dns-values.yaml` | 27 | `__SUBSCRIPTION_ID__` | `terraform output -raw subscription_id` |
| `helm-values/external-dns-values.yaml` | 35 | `__EXTERNAL_DNS_MI_CLIENT_ID__` | `terraform output -raw external_dns_managed_identity_client_id` |
| `helm-values/external-dns-values.yaml` | 36 | `__TENANT_ID__` | `terraform output -raw tenant_id` |
| `helm-values/external-dns-values.yaml` | 45 | `__EXTERNAL_DNS_MI_CLIENT_ID__` | `terraform output -raw external_dns_managed_identity_client_id` |
| `helm-values/loki-values.yaml` | 30 | `__OBS_STORAGE_ACCOUNT__` | `terraform output -raw observability_storage_account_name` |
| `helm-values/loki-values.yaml` | 51 | `__OBS_MI_CLIENT_ID__` | `terraform output -raw observability_managed_identity_client_id` |
| `helm-values/loki-values.yaml` | 52 | `__TENANT_ID__` | `terraform output -raw tenant_id` |
| `helm-values/tempo-values.yaml` | 15 | `__OBS_STORAGE_ACCOUNT__` | `terraform output -raw observability_storage_account_name` |
| `helm-values/tempo-values.yaml` | 22 | `__OBS_STORAGE_ACCOUNT__` | `terraform output -raw observability_storage_account_name` |
| `helm-values/mimir-values.yaml` | 16 | `__OBS_STORAGE_ACCOUNT__` | `terraform output -raw observability_storage_account_name` |
| `helm-values/mimir-values.yaml` | 23 | `__OBS_STORAGE_ACCOUNT__` | `terraform output -raw observability_storage_account_name` |
| `helm-values/mimir-values.yaml` | 30 | `__OBS_STORAGE_ACCOUNT__` | `terraform output -raw observability_storage_account_name` |
| `helm-values/mimir-values.yaml` | 37 | `__OBS_STORAGE_ACCOUNT__` | `terraform output -raw observability_storage_account_name` |
| `helm-values/kube-prometheus-stack-values.yaml` | 77 | `__ALERT_FROM_EMAIL__` | your sending Gmail |
| `helm-values/kube-prometheus-stack-values.yaml` | 138 | `__ALERT_FROM_EMAIL__` | your sending Gmail |
| `helm-values/kube-prometheus-stack-values.yaml` | 140 | `__ALERT_FROM_EMAIL__` | your sending Gmail |
| `helm-values/kube-prometheus-stack-values.yaml` | 152 | `__ALERT_TO_EMAIL__` | where alerts go |
| `infra-manifests/cert-manager-clusterissuer.yaml` | 15 | `__ALERT_FROM_EMAIL__` | your email (LE registers it) |
| `infra-manifests/cert-manager-clusterissuer.yaml` | 21 | `__SUBSCRIPTION_ID__` | `terraform output -raw subscription_id` |
| `infra-manifests/cert-manager-clusterissuer.yaml` | 24 | `__TENANT_ID__` | `terraform output -raw tenant_id` |
| `infra-manifests/cert-manager-clusterissuer.yaml` | 26 | `__EXTERNAL_DNS_MI_CLIENT_ID__` | `terraform output -raw external_dns_managed_identity_client_id` |
| `infra-manifests/eso-clustersecretstore.yaml` | 12 | `__KEY_VAULT_URI__` | `terraform output -raw key_vault_uri` |
| `infra-manifests/eso-clustersecretstore.yaml` | 13 | `__TENANT_ID__` | `terraform output -raw tenant_id` |

After editing, **commit and push to `sbom-platform/main`**. Argo CD reads from the repo, so the substituted values must be in Git for Argo to apply them in step 5.

```sh
cd sbom-platform
git add -A
git commit -m "chore: substitute Terraform output values"
git push origin main
```

---

## 5. Run bootstrap scripts

From `sbom-platform/bootstrap/`. Each script is idempotent.

```sh
cd sbom-platform/bootstrap
chmod +x *.sh

# Step 1: Add Helm chart repos
./00-helm-repos.sh

# Step 2: cert-manager + Let's Encrypt staging ClusterIssuer
./01-cert-manager.sh
# Expected: 5-7 pods Running in `cert-manager` ns; ClusterIssuer `letsencrypt-staging` Ready

# Step 3: Istio (base + istiod + ingress gateway)
./02-istio.sh
# Expected: 3 pods Running in `istio-system`; LoadBalancer Service has an external IP
# This will print the LB IP — note it. ExternalDNS will publish A records for *.reon.buzz pointing here.

# Step 4: Argo CD
./03-argocd.sh
# Expected: 7 pods Running in `argocd` ns; prints initial admin password

# Step 5: app-of-apps (Argo CD takes over)
./04-app-of-apps.sh
```

After step 5, Argo CD installs all remaining components in dependency order over ~5–10 minutes:

```sh
kubectl -n argocd get applications -w
```

Expected ordering (sync waves):
1. external-secrets-operator (wave -90)
2. external-dns (wave -80), gatekeeper (wave -70)
3. gatekeeper-policies (wave -60), platform-services (wave -50)
4. kube-prometheus-stack (wave -40)
5. loki (wave -35)
6. tempo, mimir (wave -30)
7. opentelemetry-collector (wave -25), promtail (wave -20)
8. observability-config (wave -15), ingress (wave -10)
9. sbom-app-dev (wave 0)

---

## 6. Verify

### 6a. Cert + DNS

```sh
# Wildcard cert issued
kubectl -n istio-system get certificate reon-buzz-wildcard
# READY=True

# A records published by ExternalDNS
az network dns record-set list -g sa -z reon.buzz -o table | grep -i a
# Expect rows for reon.buzz, argocd.reon.buzz, grafana.reon.buzz, prometheus.reon.buzz
```

DNS propagation can take a few minutes after ExternalDNS first runs. Use `nslookup argocd.reon.buzz` to check.

### 6b. Argo CD UI

Open https://argocd.reon.buzz from `37.60.98.75`. (Other IPs get blocked by AuthorizationPolicy — feature, not bug.)

Login: `admin` / password from `kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d`. **Rotate immediately** via UI.

### 6c. Grafana

Open https://grafana.reon.buzz. Login: `admin` / value of `terraform output -raw grafana_admin_password`.

In Explore:
- **Mimir** — query `up` → should return ~30 series
- **Loki** — query `{namespace="argocd"}` → should return Argo CD pod logs
- **Tempo** — search by service `istio-ingressgateway` → should return traces

### 6d. Workload Identity sanity

```sh
# Pick a Loki pod
POD=$(kubectl -n observability get pod -l app.kubernetes.io/name=loki -o jsonpath='{.items[0].metadata.name}')
kubectl -n observability exec "$POD" -- ls /var/run/secrets/azure/tokens/azure-identity-token
# File exists = WI webhook fired = pod label is correct

# Confirm storage write actually worked
az storage blob list --account-name "$(cd ../sbom-analyzer/infra && terraform output -raw observability_storage_account_name)" \
  --container-name loki --auth-mode login -o table | head
# Expect blobs starting to appear within a few minutes of Loki starting
```

If the projected token file is missing, the chart's `podLabels.azure.workload.identity/use: "true"` didn't propagate — restart the deployment.

---

## 7. Rollback / teardown

### Roll back a single Argo CD Application

```sh
argocd app rollback <app-name>
# or via UI: pick a previous synced revision
```

### Stop everything but keep the cluster

```sh
kubectl delete -f sbom-platform/argocd/argocd-apps.yaml
helm uninstall argocd -n argocd
helm uninstall istio-ingressgateway istiod istio-base -n istio-system
helm uninstall cert-manager -n cert-manager
```

### Burn everything down

```sh
cd sbom-analyzer/infra
terraform destroy
```

KV soft-delete is 7 days; the storage account survives `destroy` if `purge_protection_enabled` is true (it's not in this config, so it's fully gone).

---

## Common failure modes (and what to check first)

| Symptom | Most likely cause | First check |
|---|---|---|
| `cert-manager` Certificate stuck `Ready=False` for >5 min | DNS-01 challenge can't authenticate to Azure DNS | `kubectl -n cert-manager logs -l app=cert-manager` — look for `AADSTS` errors. Verify external_dns MI has DNS Zone Contributor on `reon.buzz`. |
| Loki/Tempo/Mimir Pod `CrashLoopBackOff` with `unauthorized` from blob | Workload Identity token not mounted | `kubectl exec ... -- env | grep AZURE_` — should show client+tenant ID. If empty, pod label `azure.workload.identity/use: "true"` is missing. |
| `argocd.reon.buzz` returns connection refused | DNS not propagated yet, or LB external IP not assigned | `kubectl -n istio-system get svc istio-ingressgateway` — check EXTERNAL-IP. `nslookup argocd.reon.buzz` — should resolve. |
| Argo CD Application stuck `OutOfSync` with `manifest generation failed` | Helm values file references a chart version that no longer exists | Check `argocd/apps/<name>.yaml` `targetRevision`; bump to a current version on the chart repo. |
| Gatekeeper rejects pod with `disallowed image registry` | A new component's registry isn't in the allowlist | Edit `policies/gatekeeper/constraints/allowed-registries-cluster.yaml`, add the registry, push. Argo CD will sync the constraint update. |
| Grafana login fails with bad credentials | `grafana-admin` Secret didn't sync from KV | `kubectl -n observability get externalsecret grafana-admin -o yaml` — look at status. Most likely: ESO MI federated credential subject doesn't match the actual SA. |

---

## What's deliberately NOT in this runbook

- **Production hardening.** Currently: public API server, public Argo CD UI (with IP allowlist), Let's Encrypt staging certs, no PodSecurity admission, single replicas everywhere. Move-to-prod checklist would be its own doc.
- **Backup / DR.** Cluster state lives in Argo CD's git source. Volume data (Prometheus PVC, Loki blob storage) is not backed up. For dev that's fine.
- **Multi-cluster.** Single cluster. Adding more would mean reworking the Argo CD destination per Application.

If you hit something this doc doesn't cover, the next doc to write is `troubleshooting.md` — capture what failed and what fixed it. Keep it close to where it'll get re-read.
