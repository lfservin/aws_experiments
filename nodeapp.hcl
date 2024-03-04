
provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "my_key" {
  description = "KMS key for encrypting secrets"
  enable_key_rotation = true
  policy      = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "key-default-1",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_AWS_ACCOUNT_ID:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_secretsmanager_secret" "db_password" {
  name            = "my_db_password"
  kms_key_id      = aws_kms_key.my_key.arn
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    password = random_password.db_password.result
  })
}


# ECR for storing Docker images
resource "aws_ecr_repository" "app_repository" {
  name = "app-repository"
  image_scanning_configuration {
    scan_on_push = true
  }
  image_tag_mutability = "IMMUTABLE"
}

# VPC, Subnets, and Security Group
resource "aws_vpc" "app_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "app_subnet" {
  count      = 2
  vpc_id     = aws_vpc.app_vpc.id
  cidr_block = count.index == 0 ? "10.0.1.0/24" : "10.0.2.0/24"
}

resource "aws_security_group" "app_sg" {
  vpc_id = aws_vpc.app_vpc.id
}

# RDS PostgreSQL Database
resource "aws_db_instance" "app_db" {
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = random_password.db_password.result
  db_name              = "appdb"
  skip_final_snapshot  = true
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  depends_on = [aws_secretsmanager_secret_version.db_password]
}

# IAM Role for ECS Task
resource "aws_iam_role" "ecs_task_role" {
  name = "ecs_task_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      },
      Effect = "Allow",
    }],
  })
}

# ECS Cluster
resource "aws_ecs_cluster" "app_cluster" {
  name = "app-cluster"
}

# ECS Task Definition
resource "aws_ecs_task_definition" "app_task" {
  family                   = "app-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([{
    name      = "app-container",
    image     = "${aws_ecr_repository.app_repository.repository_url}:latest",
    cpu       = 256,
    memory    = 512,
    essential = true,
    portMappings = [{
      containerPort = 80,
      hostPort      = 80,
      protocol      = "tcp"
    }],
  }])
}

# Application Load Balancer
resource "aws_lb" "app_lb" {
  name               = "app-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = aws_subnet.app_subnet[*].id
  security_groups    = [aws_security_group.app_sg.id]
    access_logs {
    bucket  = aws_s3_bucket.lb_logs.bucket
    prefix  = "myapp"
    enabled = true
  }
}

resource "aws_s3_bucket" "lb_logs" {
  bucket = "my-alb-logs-bucket"
  acl    = "private"
}

resource "aws_lb_target_group" "app_tg" {
  name     = "app-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.app_vpc.id
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

# ECS Service
resource "aws_ecs_service" "app_service" {
  name            = "app-service"
  cluster         = aws_ecs_cluster.app_cluster.id
  task_definition = aws_ecs_task_definition.app_task.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg.arn
    container_name   = "app-container"
    container_port   = 80
  }

  network_configuration {
    subnets          = aws_subnet.app_subnet[*].id
    security_groups  = [aws_security_group.app_sg.id]
    assign_public_ip = true
  }
}
