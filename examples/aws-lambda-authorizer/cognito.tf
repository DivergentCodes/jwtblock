################################################################################
# Variables
################################################################################

resource "random_id" "domain_suffix" {
  byte_length = 8
}

locals {
  cognito_user_pool_name  = "${var.project_name}-user-pool"
  cognito_app_client_name = "${var.project_name}-app-client"
  domain_prefix           = "${var.project_name}-${random_id.domain_suffix.hex}"
}

################################################################################
# User Pool
################################################################################

resource "aws_cognito_user_pool" "main" {
  name = local.cognito_user_pool_name

  password_policy {
    minimum_length    = 8
    require_lowercase = false
    require_numbers   = false
    require_symbols   = false
    require_uppercase = false
  }

  auto_verified_attributes = ["email"]
}


################################################################################
# App Client
################################################################################

resource "aws_cognito_user_pool_client" "main" {
  name         = local.cognito_app_client_name
  user_pool_id = aws_cognito_user_pool.main.id

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = local.scopes
  allowed_oauth_flows_user_pool_client = true

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_CUSTOM_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
  ]

  callback_urls                = local.oidc_callback_urls
  logout_urls                  = local.oidc_logout_urls
  supported_identity_providers = ["COGNITO"]

  generate_secret = false
}


################################################################################
# Domain
################################################################################

resource "aws_cognito_user_pool_domain" "main" {
  domain       = local.domain_prefix
  user_pool_id = aws_cognito_user_pool.main.id
}


################################################################################
# User
################################################################################

resource "aws_cognito_user" "bob" {
  user_pool_id = aws_cognito_user_pool.main.id
  username     = var.idp_demo_user.username
  password     = var.idp_demo_user.password

  attributes = {
    email          = var.idp_demo_user.email
    email_verified = true
  }
}
