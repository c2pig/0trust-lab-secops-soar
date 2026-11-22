output "pages_project_name" {
  description = "Cloudflare Pages project name."
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
