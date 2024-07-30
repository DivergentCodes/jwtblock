###########################################################
# Security Group
###########################################################

resource "aws_security_group" "jwtblock_lambda" {
  name        = "${var.project_name}-jwtblock-lambda-sg"
  description = "The JWT Block Lambda endpoints and authorizer"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.project_name}-jwtblock-lambda-sg"
  }
}

resource "aws_security_group_rule" "jwtblock_lambda_egress_all" {
  security_group_id = aws_security_group.jwtblock_lambda.id

  description = "Allow all JWT Block Lambda traffic out"
  type        = "egress"
  protocol    = "-1"
  from_port   = 0
  to_port     = 0
  cidr_blocks = ["0.0.0.0/0"]
}

###########################################################
# IAM Role & Policy
###########################################################

resource "aws_iam_role" "jwtblock_lambda_role" {
  name = "${var.project_name}-jwtblock-lambda-role"

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

resource "aws_iam_role_policy" "jwtblock_lambda_policy" {
  role = aws_iam_role.jwtblock_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:AttachNetworkInterface",
          "ec2:DetachNetworkInterface",
        ]
        Effect = "Allow"
        Resource = "*"
      },
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

resource "aws_iam_role_policy_attachment" "jwtblock_lambda_exec_policy_attachment" {
  role       = aws_iam_role.jwtblock_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

###########################################################
# Lambda Function
###########################################################

data "archive_file" "jwtblock_lambda" {
  # The binary must be named "bootstrap"
  # https://docs.aws.amazon.com/lambda/latest/dg/golang-handler.html#golang-handler-naming
  source_file = "./bootstrap"
  output_path = "lambda_jwtblock.zip"
  type        = "zip"
}

resource "aws_lambda_function" "jwtblock" {
  description   = "JWT Block API endpoints and Lambda authorizer"
  function_name = "${var.project_name}-authorizer"
  role          = aws_iam_role.jwtblock_lambda_role.arn
  handler       = "main"
  filename      = "lambda_jwtblock.zip"
  source_code_hash = data.archive_file.jwtblock_lambda.output_base64sha256
  runtime       = "provided.al2023"

  environment {
    variables = {
      JWTBLOCK_DEBUG                     = 1
      JWTBLOCK_REDIS_HOST                = aws_elasticache_cluster.redis.cache_nodes[0].address
      JWTBLOCK_REDIS_PORT                = var.redis_port
      JWTBLOCK_HTTP_CORS_ALLOWED_ORIGINS = "https://${aws_cloudfront_distribution.static_assets.domain_name}"
    }
  }

  vpc_config {
    subnet_ids = [
      aws_subnet.private_subnet_a.id,
      aws_subnet.private_subnet_b.id,
    ]

    security_group_ids = [ aws_security_group.jwtblock_lambda.id ]
  }

  depends_on = [
    aws_iam_role_policy.jwtblock_lambda_policy,
    data.archive_file.jwtblock_lambda,
  ]
}

###########################################################
# API Gateway Endpoint (HTTP)
###########################################################

resource "aws_lambda_permission" "jwtblock" {
  function_name = aws_lambda_function.jwtblock.function_name
  statement_id  = "AllowAPIGatewayInvoke"
  principal     = "apigateway.amazonaws.com"
  action        = "lambda:InvokeFunction"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "jwtblock" {
  description            = "APIGW v2 integration to the JWT Block Lambda handler"
  api_id                 = aws_apigatewayv2_api.main.id
  integration_uri        = aws_lambda_function.jwtblock.invoke_arn
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "jwtblock" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "ANY /blocklist"
  target    = "integrations/${aws_apigatewayv2_integration.jwtblock.id}"
}

resource "aws_apigatewayv2_authorizer" "jwtblock" {
  name                              = "${var.project_name}-authorizer"
  api_id                            = aws_apigatewayv2_api.main.id
  authorizer_uri                    = aws_lambda_function.jwtblock.invoke_arn
  authorizer_type                   = "REQUEST"
  identity_sources                  = ["$request.header.Authorization"]
  authorizer_payload_format_version = "2.0"
}