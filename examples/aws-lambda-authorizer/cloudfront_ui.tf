locals {
  s3_origin_id = var.project_name

  static_assets = [
    {
      source = "./ui-app/index.html",
      dest   = "index.html",
      mime   = "text/html",
    },
    {
      source = "./ui-app/oauth2-callback.html",
      dest   = "oauth2-callback.html",
      mime   = "text/html",
    },
    {
      source = "./ui-app/styles.css",
      dest   = "styles.css",
      mime   = "text/css",
    },
    {
      source = "./ui-app/oidc.js",
      dest   = "oidc.js",
      mime   = "application/javascript",
    },
  ]
}

###########################################################
# S3 Bucket
###########################################################

resource "aws_s3_bucket" "static_assets" {
  bucket = var.project_name
}

###########################################################
# Static Assets (UI)
###########################################################

resource "aws_s3_object" "ui_config" {
  bucket = aws_s3_bucket.static_assets.id

  content = templatefile("${path.module}/ui-app/config.json.tpl", {
    oidc_client_id     = local.oidc_client_id
    oidc_authorize_url = local.oidc_authorize_url
    oidc_token_url     = local.oidc_token_url
    oidc_callback_url  = local.oidc_callback_urls[0]
    oidc_logout_url    = local.oidc_logout_urls[0]
    protected_url      = local.protected_url
  })

  key          = "config.json"
  content_type = "application/json"
}

resource "aws_s3_object" "static_assets" {
  for_each = { for item in local.static_assets: item.dest => item }

  bucket       = aws_s3_bucket.static_assets.id
  source       = each.value.source
  key          = each.value.dest
  content_type = each.value.mime
  etag         = filemd5(each.value.source)
}

###########################################################
# Permissions
###########################################################

resource "aws_cloudfront_origin_access_identity" "static_assets" {
  comment = var.project_name
}

resource "aws_s3_bucket_policy" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${aws_cloudfront_origin_access_identity.static_assets.id}"
        },
        Action   = "s3:GetObject",
        Resource = "${aws_s3_bucket.static_assets.arn}/*"
      }
    ]
  })
}

###########################################################
# Cloudfront
###########################################################

resource "aws_cloudfront_origin_access_control" "static_assets" {
  name                              = var.project_name
  description                       = "Policy for the web UI of ${var.project_name}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_response_headers_policy" "static_assets" {
  name    = var.project_name
  comment = var.project_name

  cors_config {
    access_control_allow_credentials = true

    access_control_allow_origins {
      items = ["*"]
    }

    access_control_allow_headers {
      items = ["Authorization"]
    }

    access_control_allow_methods {
      items = ["OPTIONS", "GET", "POST"]
    }

    origin_override = true
  }

  security_headers_config {
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "same-origin"
      override        = true
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
    strict_transport_security {
      include_subdomains         = true
      access_control_max_age_sec = "63072000"
      override                   = true
    }
  }
}

resource "aws_cloudfront_distribution" "static_assets" {
  enabled             = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"

  origin {
    origin_id                = local.s3_origin_id
    domain_name              = aws_s3_bucket.static_assets.bucket_regional_domain_name

    s3_origin_config {
      origin_access_identity   = aws_cloudfront_origin_access_identity.static_assets.cloudfront_access_identity_path
    }
  }


  default_cache_behavior {
    target_origin_id           = local.s3_origin_id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.static_assets.id
    viewer_protocol_policy     = "allow-all"
    min_ttl                    = 0
    default_ttl                = 1
    max_ttl                    = 1

    cached_methods   = [
      "OPTIONS",
      "HEAD",
      "GET",
    ]
    allowed_methods  = [
      "OPTIONS",
      "HEAD",
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
    ]

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
