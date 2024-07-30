###########################################################
# Security Group
###########################################################

resource "aws_security_group" "protected_lambda" {
  name        = "${var.project_name}-protected-lambda-sg"
  description = "The protected Lambda API endpoints"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.project_name}-protected-lambda-sg"
  }
}

resource "aws_security_group_rule" "protected_lambda_egress_all" {
  security_group_id = aws_security_group.protected_lambda.id

  description = "Allow all protected Lambda traffic out"
  type        = "egress"
  protocol    = "-1"
  from_port   = 0
  to_port     = 0
  cidr_blocks = ["0.0.0.0/0"]
}

###########################################################
# IAM Role & Policy
###########################################################

resource "aws_iam_role" "protected_lambda_role" {
  name = "${var.project_name}-protected-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Effect = "Allow"
      }
    ]
  })
}

resource "aws_iam_role_policy" "protected_lambda_policy" {
  role = aws_iam_role.protected_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Effect = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "protected_lambda_exec_policy_attachment" {
  role       = aws_iam_role.protected_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

###########################################################
# Lambda Function
###########################################################

data "archive_file" "protected_lambda" {
  # The binary must be named "bootstrap"
  # https://docs.aws.amazon.com/lambda/latest/dg/golang-handler.html#golang-handler-naming
  source_file = "./lambda_protected.py"
  output_path = "lambda_protected.zip"
  type        = "zip"
}

resource "aws_lambda_function" "protected" {
  description   = "Protected API endpoints"
  function_name = "${var.project_name}-protected"
  role          = aws_iam_role.protected_lambda_role.arn
  handler       = "lambda_protected.lambda_handler"
  filename      = "lambda_protected.zip"
  source_code_hash = data.archive_file.protected_lambda.output_base64sha256
  runtime       = "python3.12"

  environment {
    variables = {
      LOG_LEVEL = "DEBUG"
    }
  }

  depends_on = [
    aws_iam_role_policy.protected_lambda_policy,
    data.archive_file.protected_lambda,
  ]
}

###########################################################
# API Gateway Endpoint (HTTP)
###########################################################

resource "aws_lambda_permission" "protected" {
  function_name = aws_lambda_function.protected.function_name
  statement_id  = "AllowAPIGatewayInvoke"
  principal     = "apigateway.amazonaws.com"
  action        = "lambda:InvokeFunction"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "protected" {
  description            = "APIGW v2 integration to protected Lambda handler"
  api_id                 = aws_apigatewayv2_api.main.id
  integration_uri        = aws_lambda_function.protected.invoke_arn
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# Allow preflight requests to protected endpoint without authentication.
resource "aws_apigatewayv2_route" "protected_preflight" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "OPTIONS /protected"
  target    = "integrations/${aws_apigatewayv2_integration.protected.id}"
}

# Require authentication for requests to protected endpoint.
resource "aws_apigatewayv2_route" "protected_requests" {
  for_each = toset(["GET", "POST"])

  api_id    = aws_apigatewayv2_api.main.id
  route_key = "${each.value} /protected"
  target    = "integrations/${aws_apigatewayv2_integration.protected.id}"

  authorizer_id      = aws_apigatewayv2_authorizer.jwtblock.id
  authorization_type = "CUSTOM"
}