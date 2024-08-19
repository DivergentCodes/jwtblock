output "api_gatewayv2_http_base_url" {
  description = "Base URL for the HTTP API Gateway v2 endpoints"
  value       = local.apigw_base_url
}

output "cloudfront_ui_url" {
  description = "Base URL for the Cloudfront UI app"
  value       = local.ui_origin
}

output "ui_config_url" {
  description = "UI config file"
  value       = "${local.ui_origin}/config.json"
}

output "protected_url" {
  value = local.protected_url
}

output "odic_issuer" {
  value = local.issuer
}

output "jwks_url" {
  value = local.jwks_url
}

output "oidc_configuration" {
  value = {
    client_id     = local.oidc_client_id
    authorize_url = local.oidc_authorize_url
    token_url     = local.oidc_token_url
    callback_url  = local.oidc_callback_urls[0]
    logout_url    = local.oidc_logout_urls[0]
  }
}