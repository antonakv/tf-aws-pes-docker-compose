# tf-aws-docker-compose
Terraform Enterprise FDO docker compose

## Requirements

- To add

## Preparation

- Login to the quai.io

- In the Account settings click `Generate Encrypted Password`

- Add variable value to terraform.tfvars called `docker_quaiio_token` from -p="token_value_here" generated on the previous step.

- Create variable values file terraform.tfvars

```
region                  = "eu-north-1"
tfe_license_path        = "upload/license.lic"
cidr_vpc                = "10.5.0.0/16"
cidr_subnet_private_1   = "10.5.1.0/24"
cidr_subnet_private_2   = "10.5.2.0/24"
cidr_subnet_public_1    = "10.5.3.0/24"
cidr_subnet_public_2    = "10.5.4.0/24"
key_name                = "aakulov2"
aws_ami                 = "ami-0b3a606764400b644"
db_instance_type        = "db.t3.xlarge"
instance_type           = "t3.2xlarge"
release_sequence        = 722
tfe_hostname            = "tfe.domain-name-here.com"
postgres_db_name        = "mydbtfe"
postgres_engine_version = "14.4"
postgres_username       = "postgres"
ssl_cert_path           = "cert.pem"
ssl_key_path            = "privkey.pem"
ssl_chain_path          = "chain.pem"
ssl_fullchain_cert_path = "fullchain.pem"
domain_name             = "domain-name-here.com"
cloudflare_zone_id      = "zone_id_here"
cloudflare_api_token    = "api_token_here"
lb_ssl_policy           = "ELBSecurityPolicy-2016-08"
aws_az_1                = "eu-north-1b"
aws_az_2                = "eu-north-1c"
docker_quaiio_login     = "docker login here"
docker_quaiio_token     = "docker token here"
tfe_quaiio_tag          = "3bc2fb8"

```

## Retrieve admin token

On the instance ssh session run: `sudo docker exec -it terraform-enterprise-1 bash -c "/usr/local/bin/retrieve-iact"`
