# providers.tf

terraform {

  required_version = "~> 1.9.0"

  required_providers {
  }

}

provider "aws" {

  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy   = "terraform"
      Name        = var.project_name
      Project     = var.project_name
    }
  }
}
