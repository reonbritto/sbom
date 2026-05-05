# ─────────────────────────────────────────────────────────
#  Data Sources
# ─────────────────────────────────────────────────────────

data "azurerm_client_config" "current" {}

# Reference the existing DNS zone (already created in resource group "sa")
data "azurerm_dns_zone" "main" {
  name                = var.dns_zone_name
  resource_group_name = var.dns_zone_resource_group
}

# ─────────────────────────────────────────────────────────
#  Resource Group
# ─────────────────────────────────────────────────────────

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    project     = "sbom-analyzer"
    environment = "dev"
    managed_by  = "terraform"
  }
}

# ─────────────────────────────────────────────────────────
#  Virtual Network + AKS Subnet
# ─────────────────────────────────────────────────────────

resource "azurerm_virtual_network" "main" {
  name                = var.vnet_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = [var.vnet_cidr]

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_subnet" "aks" {
  name                 = "snet-aks"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.aks_subnet_cidr]
}

# ─────────────────────────────────────────────────────────
#  AKS Cluster
# ─────────────────────────────────────────────────────────

resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = var.cluster_name
  sku_tier            = "Free"

  default_node_pool {
    name                 = "default"
    vm_size              = var.node_vm_size
    node_count           = var.node_count
    auto_scaling_enabled = true
    min_count            = var.node_min_count
    max_count            = var.node_max_count
    os_disk_size_gb      = 30
    max_pods             = 110
    vnet_subnet_id       = azurerm_subnet.aks.id

    upgrade_settings {
      max_surge = "10%"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  # Enable OIDC issuer for Workload Identity
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
    service_cidr      = "10.30.0.0/16"
    dns_service_ip    = "10.30.0.10"
  }

  tags = azurerm_resource_group.main.tags
}

# Cluster identity needs Network Contributor on the VNet to wire LBs/NSGs.
resource "azurerm_role_assignment" "aks_network_contributor" {
  scope                = azurerm_virtual_network.main.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_kubernetes_cluster.main.identity[0].principal_id
}

# Caller becomes cluster-admin via Azure RBAC so kubectl works without --admin.
resource "azurerm_role_assignment" "caller_cluster_admin" {
  scope                = azurerm_kubernetes_cluster.main.id
  role_definition_name = "Azure Kubernetes Service RBAC Cluster Admin"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ─────────────────────────────────────────────────────────
#  Azure Key Vault
# ─────────────────────────────────────────────────────────

# KV names are globally unique. Suffix avoids collisions if the chosen name is
# already taken (or recently soft-deleted).
resource "random_string" "kv_suffix" {
  length  = 5
  upper   = false
  special = false
  numeric = true
}

resource "azurerm_key_vault" "main" {
  name                       = "${var.key_vault_name}-${random_string.kv_suffix.result}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  tags = azurerm_resource_group.main.tags
}

# Grant the current user (deployer) "Key Vault Secrets Officer" so Terraform can write secrets.
resource "azurerm_role_assignment" "kv_deployer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ─────────────────────────────────────────────────────────
#  Key Vault Secrets
# ─────────────────────────────────────────────────────────

resource "random_password" "service_api_key" {
  length  = 32
  special = true
}

resource "azurerm_key_vault_secret" "azure_tenant_id" {
  name         = "azure-tenant-id"
  value        = data.azurerm_client_config.current.tenant_id
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]
}

resource "azurerm_key_vault_secret" "service_api_key" {
  name         = "service-api-key"
  value        = random_password.service_api_key.result
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  lifecycle {
    ignore_changes = [value, tags]
  }
}

resource "azurerm_key_vault_secret" "gf_admin_password" {
  name         = "gf-admin-password"
  value        = var.grafana_admin_password
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  lifecycle {
    ignore_changes = [value, tags]
  }
}

resource "azurerm_key_vault_secret" "alertmanager_smtp_username" {
  name         = "alertmanager-smtp-username"
  value        = var.alertmanager_smtp_username
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  lifecycle {
    ignore_changes = [value, tags]
  }
}

resource "azurerm_key_vault_secret" "alertmanager_smtp_password" {
  name         = "alertmanager-smtp-password"
  value        = var.alertmanager_smtp_password
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  lifecycle {
    ignore_changes = [value, tags]
  }
}

# ─────────────────────────────────────────────────────────
#  Managed Identity — External Secrets Operator (ESO)
# ─────────────────────────────────────────────────────────

resource "azurerm_user_assigned_identity" "eso" {
  name                = "id-sbom-eso"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_role_assignment" "eso_kv_reader" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.eso.principal_id
}

resource "azurerm_federated_identity_credential" "eso" {
  name                      = "fc-sbom-eso"
  user_assigned_identity_id = azurerm_user_assigned_identity.eso.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.main.oidc_issuer_url
  # ESO runs in its own namespace (external-secrets), NOT in app_namespace.
  # Earlier this used `${var.app_namespace}:eso-service-account` which produced
  # `sbom:eso-service-account` — wrong. AAD rejected the token swap with
  # AADSTS700213.
  subject = "system:serviceaccount:external-secrets:eso-service-account"
}

# ─────────────────────────────────────────────────────────
#  Managed Identity — ExternalDNS
# ─────────────────────────────────────────────────────────

resource "azurerm_user_assigned_identity" "external_dns" {
  name                = "id-sbom-external-dns"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_role_assignment" "external_dns_zone" {
  scope                = data.azurerm_dns_zone.main.id
  role_definition_name = "DNS Zone Contributor"
  principal_id         = azurerm_user_assigned_identity.external_dns.principal_id
}

resource "azurerm_federated_identity_credential" "external_dns" {
  name                      = "fc-sbom-external-dns"
  user_assigned_identity_id = azurerm_user_assigned_identity.external_dns.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.main.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.external_dns_namespace}:external-dns-sa"
}

# cert-manager reuses the ExternalDNS MI for DNS-01 ACME challenges (same
# DNS Zone Contributor role on reon.buzz). Separate FIC because the K8s
# ServiceAccount running cert-manager is different from external-dns-sa.
resource "azurerm_federated_identity_credential" "cert_manager" {
  name                      = "fc-sbom-cert-manager"
  user_assigned_identity_id = azurerm_user_assigned_identity.external_dns.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.main.oidc_issuer_url
  subject                   = "system:serviceaccount:cert-manager:cert-manager"
}

# ─────────────────────────────────────────────────────────
#  Observability — Azure Storage for LGTM (Loki/Tempo/Mimir)
# ─────────────────────────────────────────────────────────

# Storage account names: 3-24 chars, lowercase + digits, globally unique.
resource "random_string" "obs_suffix" {
  length  = 6
  upper   = false
  special = false
  numeric = true
}

resource "azurerm_storage_account" "observability" {
  name                            = "stsbomobs${random_string.obs_suffix.result}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = true # Loki/Tempo/Mimir support both AAD and key auth; keep both available

  blob_properties {
    versioning_enabled = false
  }

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_storage_container" "loki" {
  name                  = "loki"
  storage_account_id    = azurerm_storage_account.observability.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "tempo" {
  name                  = "tempo"
  storage_account_id    = azurerm_storage_account.observability.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "mimir" {
  name                  = "mimir"
  storage_account_id    = azurerm_storage_account.observability.id
  container_access_type = "private"
}

resource "azurerm_user_assigned_identity" "observability" {
  name                = "id-sbom-observability"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_role_assignment" "observability_blob_contributor" {
  scope                = azurerm_storage_account.observability.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.observability.principal_id
}

# Single federated credential mapped to a shared SA name; all of Loki/Tempo/Mimir
# can use the same SA (`obs-sa`) in the observability namespace.
resource "azurerm_federated_identity_credential" "observability" {
  name                      = "fc-sbom-observability"
  user_assigned_identity_id = azurerm_user_assigned_identity.observability.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.main.oidc_issuer_url
  subject                   = "system:serviceaccount:${var.observability_namespace}:obs-sa"
}

# Caller can read storage keys for emergency / bootstrap.
resource "azurerm_role_assignment" "caller_storage_account_contrib" {
  scope                = azurerm_storage_account.observability.id
  role_definition_name = "Storage Account Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}
