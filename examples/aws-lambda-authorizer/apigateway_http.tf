###########################################################
# API Gateway (HTTP)
###########################################################

resource "aws_apigatewayv2_api" "main" {
  name          = "${var.project_name}-apigw-http"
  description   = "APIGW v2 (HTTP) for Lambdas"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = [local.ui_origin]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
    max_age = 3600  # Cache duration for preflight requests
  }
}

resource "aws_apigatewayv2_stage" "main" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "main"
  auto_deploy = true
}