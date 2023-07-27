# tf-aws-activeactive-agents instance_access

This manual is dedicated to Forward ssh and netdata ports to TFE and TFE agent instances
using AWS Network Load Balancer.

## Requirements

- Hashicorp terraform 1.5.3 version installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in .aws/credentials file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

- Configured CloudFlare DNS zone for domain `my-domain-here.com`
[Cloudflare DNS zone setup](https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/)

- SSL certificate and SSL key files for the corresponding domain name
[Certbot manual](https://certbot.eff.org/instructions)

- Created Amazon EC2 key pair for Linux instance
[Creating a public hosted zone](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)

- Provisioned with `terraform apply` root folder of the main terraform code in the repository

## Preparation 

- Change folder to instance_access

```bash
cd instance_access
```

- Create file terraform.tfvars with following contents

```
region                  = "eu-central-1"
ssl_cert_path           = "cert.pem"
ssl_key_path            = "privkey.pem"
ssl_chain_path          = "chain.pem"
ssl_fullchain_cert_path = "fullchain.pem"
domain_name             = "my-domain.com"
cloudflare_zone_id      = "xxxxxxxxxxxxxxxx"
cloudflare_api_token    = "xxxxxxxxxxxxxxxx"
lb_ssl_policy           = "ELBSecurityPolicy-2016-08"
```

## Run terraform code

- In the same folder you were before, run 

```bash
terraform init
```

Example output

```
% terraform init                  

Initializing the backend...

Initializing provider plugins...
- terraform.io/builtin/terraform is built in to Terraform
- Reusing previous version of cloudflare/cloudflare from the dependency lock file
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of hashicorp/template from the dependency lock file
- Installing cloudflare/cloudflare v4.10.0...
- Installed cloudflare/cloudflare v4.10.0 (self-signed, key ID C76001609EE3B136)
- Installing hashicorp/aws v5.9.0...
- Installed hashicorp/aws v5.9.0 (signed by HashiCorp)
- Installing hashicorp/template v2.2.0...
- Installed hashicorp/template v2.2.0 (signed by HashiCorp)

Partner and community providers are signed by their developers.
If you'd like to know more about provider signing, you can read about it here:
https://www.terraform.io/docs/cli/plugins/signing.html

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.

```

- Run the `terraform apply`

Expected result:

```
% terraform apply --auto-approve
data.terraform_remote_state.activeactive-agents: Reading...
data.terraform_remote_state.activeactive-agents: Read complete after 0s
data.aws_instances.tfe: Reading...
data.aws_instances.tfc_agent: Reading...
data.aws_instances.tfc_agent: Read complete after 0s [id=eu-north-1]
data.aws_instances.tfe: Read complete after 0s [id=eu-north-1]
data.aws_instance.tfe["i-0d13747e40fbbf808"]: Reading...
data.aws_instance.tfe["i-0d13747e40fbbf808"]: Read complete after 1s [id=i-0d13747e40fbbf808]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"] will be created
  + resource "aws_lb" "tfe_ssh_lb" {
      + arn                              = (known after apply)
      + arn_suffix                       = (known after apply)
      + dns_name                         = (known after apply)
      + enable_cross_zone_load_balancing = false
      + enable_deletion_protection       = false
      + id                               = (known after apply)
      + internal                         = (known after apply)
      + ip_address_type                  = (known after apply)
      + load_balancer_type               = "network"
      + name                             = "axxxxxx-lfwb-ssh-10-5-1-119"
      + security_groups                  = (known after apply)
      + subnets                          = [
          + "subnet-01859b1e8cb77b042",
          + "subnet-08368177726c84824",
        ]
      + tags_all                         = (known after apply)
      + vpc_id                           = (known after apply)
      + zone_id                          = (known after apply)
    }

  # aws_lb_listener.tfe_netdata["i-0d13747e40fbbf808"] will be created
  + resource "aws_lb_listener" "tfe_netdata" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 19999
      + protocol          = "TCP"
      + ssl_policy        = (known after apply)
      + tags_all          = (known after apply)

      + default_action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }
    }

  # aws_lb_listener.tfe_ssh["i-0d13747e40fbbf808"] will be created
  + resource "aws_lb_listener" "tfe_ssh" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 22
      + protocol          = "TCP"
      + ssl_policy        = (known after apply)
      + tags_all          = (known after apply)

      + default_action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }
    }

  # aws_lb_target_group.tfe_netdata["i-0d13747e40fbbf808"] will be created
  + resource "aws_lb_target_group" "tfe_netdata" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + connection_termination             = false
      + deregistration_delay               = "300"
      + id                                 = (known after apply)
      + ip_address_type                    = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancing_algorithm_type      = (known after apply)
      + load_balancing_cross_zone_enabled  = (known after apply)
      + name                               = "axxxxxx-lfwb-netdata-10-5-1-119"
      + port                               = 19999
      + preserve_client_ip                 = (known after apply)
      + protocol                           = "TCP"
      + protocol_version                   = (known after apply)
      + proxy_protocol_v2                  = false
      + slow_start                         = 0
      + tags_all                           = (known after apply)
      + target_type                        = "instance"
      + vpc_id                             = "vpc-05d6dfb943e32ddf6"

      + health_check {
          + enabled             = true
          + healthy_threshold   = 2
          + interval            = 10
          + matcher             = (known after apply)
          + path                = (known after apply)
          + port                = "traffic-port"
          + protocol            = "TCP"
          + timeout             = (known after apply)
          + unhealthy_threshold = 2
        }
    }

  # aws_lb_target_group.tfe_ssh["i-0d13747e40fbbf808"] will be created
  + resource "aws_lb_target_group" "tfe_ssh" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + connection_termination             = false
      + deregistration_delay               = "300"
      + id                                 = (known after apply)
      + ip_address_type                    = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancing_algorithm_type      = (known after apply)
      + load_balancing_cross_zone_enabled  = (known after apply)
      + name                               = "axxxxxx-lfwb-ssh-10-5-1-119"
      + port                               = 22
      + preserve_client_ip                 = (known after apply)
      + protocol                           = "TCP"
      + protocol_version                   = (known after apply)
      + proxy_protocol_v2                  = false
      + slow_start                         = 0
      + tags_all                           = (known after apply)
      + target_type                        = "instance"
      + vpc_id                             = "vpc-05d6dfb943e32ddf6"

      + health_check {
          + enabled             = true
          + healthy_threshold   = 2
          + interval            = 10
          + matcher             = (known after apply)
          + path                = (known after apply)
          + port                = "traffic-port"
          + protocol            = "TCP"
          + timeout             = (known after apply)
          + unhealthy_threshold = 2
        }
    }

  # aws_lb_target_group_attachment.tfe_netdata["i-0d13747e40fbbf808"] will be created
  + resource "aws_lb_target_group_attachment" "tfe_netdata" {
      + id               = (known after apply)
      + port             = 19999
      + target_group_arn = (known after apply)
      + target_id        = "i-0d13747e40fbbf808"
    }

  # aws_lb_target_group_attachment.tfe_ssh["i-0d13747e40fbbf808"] will be created
  + resource "aws_lb_target_group_attachment" "tfe_ssh" {
      + id               = (known after apply)
      + port             = 22
      + target_group_arn = (known after apply)
      + target_id        = "i-0d13747e40fbbf808"
    }

  # cloudflare_record.tfe_ssh["i-0d13747e40fbbf808"] will be created
  + resource "cloudflare_record" "tfe_ssh" {
      + allow_overwrite = false
      + created_on      = (known after apply)
      + hostname        = (known after apply)
      + id              = (known after apply)
      + metadata        = (known after apply)
      + modified_on     = (known after apply)
      + name            = "10-5-1-119"
      + proxiable       = (known after apply)
      + ttl             = 1
      + type            = "CNAME"
      + value           = (known after apply)
      + zone_id         = (sensitive value)
    }

Plan: 8 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + ssh_agent_host_names = {}
  + ssh_tfe_host_names   = {
      + i-0d13747e40fbbf808 = "10-5-1-119.domain.com"
    }
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Creating...
aws_lb_target_group.tfe_netdata["i-0d13747e40fbbf808"]: Creating...
aws_lb_target_group.tfe_ssh["i-0d13747e40fbbf808"]: Creating...
aws_lb_target_group.tfe_ssh["i-0d13747e40fbbf808"]: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:targetgroup/axxxxxx-lfwb-ssh-10-5-1-119/c519021d463970d0]
aws_lb_target_group_attachment.tfe_ssh["i-0d13747e40fbbf808"]: Creating...
aws_lb_target_group.tfe_netdata["i-0d13747e40fbbf808"]: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:targetgroup/axxxxxx-lfwb-netdata-10-5-1-119/fd381e9acbf80f40]
aws_lb_target_group_attachment.tfe_netdata["i-0d13747e40fbbf808"]: Creating...
aws_lb_target_group_attachment.tfe_ssh["i-0d13747e40fbbf808"]: Creation complete after 0s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:targetgroup/axxxxxx-lfwb-ssh-10-5-1-119/c519021d463970d0-20230727142348062700000001]
aws_lb_target_group_attachment.tfe_netdata["i-0d13747e40fbbf808"]: Creation complete after 0s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:targetgroup/axxxxxx-lfwb-netdata-10-5-1-119/fd381e9acbf80f40-20230727142348115500000002]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [10s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [20s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [30s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [40s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [50s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [1m0s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [1m10s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [1m20s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [1m30s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [1m40s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [1m50s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [2m0s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [2m10s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [2m20s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [2m30s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Still creating... [2m40s elapsed]
aws_lb.tfe_ssh_lb["i-0d13747e40fbbf808"]: Creation complete after 2m42s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:loadbalancer/net/axxxxxx-lfwb-ssh-10-5-1-119/4fbbf6e2bf66c635]
cloudflare_record.tfe_ssh["i-0d13747e40fbbf808"]: Creating...
aws_lb_listener.tfe_ssh["i-0d13747e40fbbf808"]: Creating...
aws_lb_listener.tfe_netdata["i-0d13747e40fbbf808"]: Creating...
aws_lb_listener.tfe_netdata["i-0d13747e40fbbf808"]: Creation complete after 0s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:listener/net/axxxxxx-lfwb-ssh-10-5-1-119/4fbbf6e2bf66c635/ac98308aa037b521]
aws_lb_listener.tfe_ssh["i-0d13747e40fbbf808"]: Creation complete after 0s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:listener/net/axxxxxx-lfwb-ssh-10-5-1-119/4fbbf6e2bf66c635/3ddf7a0128d8d5d5]
cloudflare_record.tfe_ssh["i-0d13747e40fbbf808"]: Creation complete after 2s [id=7d01fb80df2069ef11aa4bd7b295bf89]

Apply complete! Resources: 8 added, 0 changed, 0 destroyed.

Outputs:

ssh_agent_host_names = {}
ssh_tfe_host_names = {
  "i-0d13747e40fbbf808" = "10-5-1-119.domain.com"
}
```

- Use `ssh` to connect to the endpoints