# variables.tf

variable "project_name" {
  description = "The name of this project."
  type        = string
  default     = "jwtblock-lambda-example"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR for the entire VPC"
  type        = string
  default     = "10.198.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR for subnets in each availability zone"
  type        = map(string)
  default     = {
    aza = "10.198.1.0/24",
    azb = "10.198.2.0/24",
  }
}

variable "redis_port" {
  description = "Redis service port"
  type        = number
  default     = 6379
}

variable "redis_node_count" {
  description = "Redis nodes in the cluster"
  type        = number
  default     = 1
}

variable "idp_demo_user" {
  description = "The demo user to login as"
  default     = {
    username  = "bob"
    password  = "hunter22"
    email     = "bob@example.com"
  }
}