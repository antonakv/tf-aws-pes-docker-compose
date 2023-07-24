variable "region" {
  type        = string
  description = "AWS region"
}
variable "tfe_license_path" {
  type        = string
  description = "Path for the TFE license"
}
variable "cidr_vpc" {
  type        = string
  description = "Amazon EC2 VPC net"
}
variable "cidr_subnet_private_1" {
  type        = string
  description = "Amazon EC2 subnet 1 private"
}
variable "cidr_subnet_private_2" {
  type        = string
  description = "Amazon EC2 subnet 2 private"
}
variable "cidr_subnet_public_1" {
  type        = string
  description = "Amazon EC2 subnet 1 public"
}
variable "cidr_subnet_public_2" {
  type        = string
  description = "Amazon EC2 subnet 2 public"
}
variable "aws_az_1" {
  type        = string
  description = "Amazon AWS availability zone 1"
}
variable "aws_az_2" {
  type        = string
  description = "Amazon AWS availability zone 2"
}
variable "key_name" {
  description = "Name of Amazon EC2 keypair for the specific region"
}
variable "db_instance_type" {
  description = "Amazon EC2 RDS instance type"
}
variable "instance_type" {
  description = "Amazon EC2 instance type"
}
variable "tfe_hostname" {
  type        = string
  description = "Terraform Enterprise hostname"
}
variable "domain_name" {
  type        = string
  description = "Domain name"
}
variable "release_sequence" {
  type        = number
  description = "Terraform Enterprise release sequence number"
}
variable "postgres_db_name" {
  type        = string
  description = "Postgres database DB name"
}
variable "postgres_engine_version" {
  type        = string
  description = "Postgres engine version"
}
variable "postgres_username" {
  type        = string
  description = "Postgres database username"
}
variable "aws_ami" {
  type        = string
  description = "Ubuntu jammy AMI with preinstalled docker-ce=5:23.0.6-1~ubuntu.22.04~jammy docker-ce-cli=5:23.0.6-1~ubuntu.22.04~jammy"
}
variable "cloudflare_zone_id" {
  type        = string
  description = "Cloudflare DNS zone id"
  sensitive   = true
}
variable "cloudflare_api_token" {
  type        = string
  description = "Cloudflare DNS API token"
  sensitive   = true
}
variable "ssl_cert_path" {
  type        = string
  description = "SSL certificate file path"
}
variable "ssl_fullchain_cert_path" {
  type        = string
  description = "SSL fullchain cert file path"
}
variable "ssl_key_path" {
  type        = string
  description = "SSL key file path"
}
variable "ssl_chain_path" {
  type        = string
  description = "SSL chain file path"
}
variable "lb_ssl_policy" {
  type        = string
  description = "SSL policy for load balancer"
}
variable "docker_quaiio_token" {
  type        = string
  description = "Docker quai.io token from Account settings"
  sensitive   = true
}
variable "docker_quaiio_login" {
  type        = string
  description = "Docker quai.io login from Account settings"
  sensitive   = true
}
variable "tfe_quaiio_tag" {
  type        = string
  description = "Docker tfe image tag on the quai.io"
}
