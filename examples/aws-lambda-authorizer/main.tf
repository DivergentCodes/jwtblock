data "aws_region" "current" {}

locals {
  vpc_id = aws_vpc.main.id  

  idp_origin   = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.aws_region}.amazoncognito.com"
  ui_origin    = "https://${aws_cloudfront_distribution.static_assets.domain_name}"
  apigw_base_url = aws_apigatewayv2_stage.main.invoke_url

  issuer         = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
  jwks_url       = "${local.issuer}/.well-known/jwks.json"

  oidc_client_id          = aws_cognito_user_pool_client.main.id
  oidc_authorize_url      = "${local.idp_origin}/oauth2/authorize"
  oidc_token_url          = "${local.idp_origin}/oauth2/token"
  oidc_callback_urls      = ["${local.ui_origin}/oauth2-callback.html"]
  oidc_logout_urls        = ["${local.apigw_base_url}/blocklist"]
  scopes                  = ["openid", "profile", "email"]

  protected_url = "${local.apigw_base_url}/protected"
}

###########################################################
# Network
###########################################################

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_subnet" "private_subnet_a" {
  vpc_id            = local.vpc_id
  cidr_block        = var.subnet_cidr["aza"]
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "${var.project_name}-subnet-aza"
  }
}

resource "aws_subnet" "private_subnet_b" {
  vpc_id            = local.vpc_id
  cidr_block        = var.subnet_cidr["azb"]
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "${var.project_name}-subnet-azb"
  }
}