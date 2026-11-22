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
  description = "Shared STATE_KV namespace ID for lab6:soar:* keys."
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment label."
}
