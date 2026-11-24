variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare Account ID."
}

variable "cloudflare_zone_id" {
  type        = string
  description = "Cloudflare Zone ID for 0trust.dev."
}

variable "state_kv_namespace_id" {
  type        = string
  default     = ""
  description = "Legacy STATE_KV namespace ID (retained optional for CF Pages module compatibility; API state is stored in Firestore Native)."
}

variable "gcp_project_id" {
  type        = string
  description = "GCP Project ID hosting the shared Firestore Native DB, Artifact Registry, and Cloud Run services."
}

variable "gcp_region" {
  type        = string
  default     = "us-central1"
  description = "GCP region for Cloud Run service deployment."
}

variable "cloud_run_image" {
  type        = string
  description = "Container image URI in Artifact Registry (e.g. us-central1-docker.pkg.dev/<project>/0trust-labs/secops-soar:latest)."
}

variable "firestore_collection" {
  type        = string
  default     = "kv_state"
  description = "Firestore Native collection name for KV state documents."
}

variable "lab_router_secret_id" {
  type        = string
  default     = "lab-router-secret"
  description = "GCP Secret Manager secret ID for X-Lab-Router-Secret validation."
}

variable "deployer_service_account_email" {
  type        = string
  default     = ""
  description = "Optional GitHub Actions WIF deployer SA email granted scoped roles/iam.serviceAccountUser on the Lab 6 runtime SA."
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment label."
}

variable "otlp_endpoint" {
  type        = string
  default     = ""
  description = "Optional OpenTelemetry OTLP HTTP collector endpoint."
}

variable "otlp_auth_header_secret_id" {
  type        = string
  default     = ""
  description = "Optional GCP Secret Manager secret ID for OTLP_AUTH_HEADER (e.g. otlp-auth-header)."
}
