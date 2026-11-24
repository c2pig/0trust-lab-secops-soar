provider "cloudflare" {}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Static SPA hosting only (dist/); API traffic is routed by 0trust-lab-router to Cloud Run.
module "secops_soar_lab" {
  source = "git::https://github.com/c2pig/managed-infrastructure.git//modules/cloudflare-pages-lab?ref=main"

  cloudflare_account_id = var.cloudflare_account_id
  cloudflare_zone_id    = var.cloudflare_zone_id
  state_kv_namespace_id = var.state_kv_namespace_id
  pages_project_name    = "0trust-lab-secops-soar"
  enable_custom_domain  = false

  plain_env_vars = {
    ENVIRONMENT = var.environment
  }

  secret_env_vars = {}
}

# Cloud Run API backend + Firestore Native state (min_instance_count = 0, $0 idle cost).
module "cloud_run_lab" {
  source = "git::https://github.com/c2pig/managed-infrastructure.git//modules/cloud-run-lab?ref=main"

  gcp_project_id                 = var.gcp_project_id
  gcp_region                     = var.gcp_region
  lab_slug                       = "secops-soar"
  image                          = var.cloud_run_image
  environment                    = var.environment
  firestore_collection           = var.firestore_collection
  lab_router_secret_id           = var.lab_router_secret_id
  deployer_service_account_email = var.deployer_service_account_email

  plain_env_vars = merge(
    var.otlp_endpoint != "" ? { OTLP_ENDPOINT = var.otlp_endpoint } : {}
  )

  secret_env_vars = merge(
    var.otlp_auth_header_secret_id != "" ? { OTLP_AUTH_HEADER = var.otlp_auth_header_secret_id } : {}
  )
}
