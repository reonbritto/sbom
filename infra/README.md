# infra

Terraform for the dev Azure footprint backing sbom-analyzer.

## What this provisions

| Resource | Notes |
|---|---|
| Resource Group | `rg-sbom` |
| VNet + AKS subnet | `10.20.0.0/16` with `10.20.0.0/22` for nodes |
| AKS cluster | Free SKU, system-assigned identity, OIDC + Workload Identity, autoscale 1–2 × `Standard_D2as_v5`, Azure CNI + Azure NetworkPolicy |
| Azure Key Vault | RBAC-mode, standard SKU. Seeds: `service-api-key` (random), `gf-admin-password`, `alertmanager-smtp-{username,password}`, `azure-tenant-id` |
| Managed Identity — ESO | Federated to `system:serviceaccount:sbom:eso-service-account`, granted `Key Vault Secrets User` on the KV |
| Managed Identity — ExternalDNS | Federated to `system:serviceaccount:external-dns:external-dns-sa`, granted `DNS Zone Contributor` on `reon.buzz` (RG `sa`) |

**Not provisioned here** (intentional):
- Container registry — using DockerHub
- Log Analytics — observability stack runs in-cluster (Prometheus / Grafana / Loki)
- Remote state — local state for now

## Prereqs

- Azure CLI (`az login`)
- Terraform >= 1.5
- Existing Azure DNS zone `reon.buzz` in resource group `sa` (already present)

## Quick start

```sh
cd infra
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars — fill subscription_id, grafana_admin_password, SMTP vars

az login
az account set --subscription <subscription_id>

terraform init
terraform plan
terraform apply

# wire kubectl
$(terraform output -raw kube_config_command)
kubectl get nodes
```

## Cost notes (dev)

Roughly:
- AKS control plane: free (Free tier)
- 1× `Standard_D2as_v5` node: ~$70/mo (autoscaler may push to 2)
- Key Vault: pennies
- VNet, public IPs, LB: ~$5/mo until you start exposing services

Tear down with `terraform destroy` when not in use.

## Layout

```
providers.tf      provider versions + azurerm config
variables.tf      all inputs
main.tf           RG, VNet, AKS, KV, secrets, managed identities, federated creds
outputs.tf        cluster name, OIDC issuer, KV uri, MI client IDs, helm snippet
terraform.tfvars  (gitignored) actual values
```

## Roadmap (after apply)

In-cluster, via Argo CD from `sbom-platform`:
- cert-manager
- Envoy Gateway
- ExternalDNS (uses the federated identity above)
- External Secrets Operator (uses the federated identity above)
- Argo CD itself (one-shot helm install, then self-managed via app-of-apps)
- Gatekeeper + your existing constraints
- Prometheus, Grafana, Loki, Alertmanager
