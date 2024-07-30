###########################################################
# Security Group
###########################################################

resource "aws_security_group" "redis" {
  name        = "${var.project_name}-redis-sg"
  description = "Redis traffic"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.project_name}-redis-sg"
  }
}

resource "aws_security_group_rule" "redis_ingress_lambda" {
  security_group_id = aws_security_group.redis.id

  description = "Allow Lambda traffic into Redis"
  type        = "ingress"
  protocol    = "tcp"
  from_port   = var.redis_port
  to_port     = var.redis_port

  source_security_group_id = aws_security_group.jwtblock_lambda.id
}

resource "aws_security_group_rule" "redis_egress_all" {
  security_group_id = aws_security_group.redis.id

  description = "Allow all Redis traffic out"
  type        = "egress"
  protocol    = "-1"
  from_port   = 0
  to_port     = 0
  cidr_blocks = ["0.0.0.0/0"]
}

###########################################################
# Redis Cluster (ElastiCache)
###########################################################

resource "aws_elasticache_subnet_group" "redis_subnet_group" {
  name       = "${var.project_name}-redis-subnet-group"
  subnet_ids = [
    aws_subnet.private_subnet_a.id,
    aws_subnet.private_subnet_b.id,
  ]

  tags = {
    Name = "${var.project_name}-redis-subnet-group"
  }
}

resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "${var.project_name}-redis-cluster"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  parameter_group_name = "default.redis7"
  num_cache_nodes      = var.redis_node_count
  port                 = var.redis_port
  subnet_group_name    = aws_elasticache_subnet_group.redis_subnet_group.name
  security_group_ids   = [aws_security_group.redis.id]

  tags = {
    Name = "${var.project_name}-redis-cluster"
  }
}