output "pages_project_name" {
  description = "Cloudflare Pages project name for static SPA deployment."
  value       = module.secops_soar_lab.pages_project_name
}

output "pages_subdomain" {
  description = "Default Cloudflare Pages subdomain."
  value       = module.secops_soar_lab.pages_subdomain
}

output "lab_url" {
  description = "Production standalone lab URL."
  value       = module.secops_soar_lab.lab_url
}

output "cloud_run_service_name" {
  description = "GCP Cloud Run service name powering /api/secops-soar/*."
  value       = module.cloud_run_lab.service_name
}

output "cloud_run_service_uri" {
  description = "GCP Cloud Run service origin URI (configured in 0trust-lab-router)."
  value       = module.cloud_run_lab.service_uri
}

output "cloud_run_service_account_email" {
  description = "Least-privilege GCP runtime service account email for Lab 6."
  value       = module.cloud_run_lab.service_account_email
}
