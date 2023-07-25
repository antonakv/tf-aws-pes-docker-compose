output "url" {
  value       = "https://${local.tfe_hostname}/admin/account/new?token=TOKEN_RETRIEVED_IN_THE_INSTANCE_SSH_SESSION"
  description = "Login URL and token"
}
output "tfe_hostname" {
  value       = local.tfe_hostname
  description = "TFE fqdn"
}
output "ssh_key_name" {
  value       = var.key_name
  description = "SSH key name"
}
output "aws_lb_active_target_group_ips" {
  value       = join(", ", data.aws_instances.tfe.private_ips)
  description = "TFE EC2 hosts in the AWS LB target group"
}
output "aws_tfe_ec2_ids" {
  value       = toset(data.aws_instances.tfe.ids)
  description = "TFE EC2 host ids"
}
output "vpc_id" {
  value       = aws_vpc.vpc.id
  description = "ID of aws vpc"
}
output "internal_sg_id" {
  value       = aws_security_group.internal_sg.id
  description = "ID of internal security group"
}
output "friendly_name_prefix" {
  value       = local.friendly_name_prefix
  description = "Friendly name prefix"
}
output "subnet_public1_id" {
  value       = aws_subnet.subnet_public1.id
  description = "ID of aws public subnet 1"
}
output "subnet_public2_id" {
  value       = aws_subnet.subnet_public2.id
  description = "ID of aws public subnet 2"
}
output "subnet_private1_id" {
  value       = aws_subnet.subnet_private1.id
  description = "ID of aws private subnet 1"
}
output "subnet_private2_id" {
  value       = aws_subnet.subnet_private2.id
  description = "ID of aws private subnet 2"
}
output "region" {
  value       = var.region
  description = "AWS region"
}
output "daemon_password" {
  value       = random_string.password.result
  description = "Replicated port 8800 authentication password"
}
