terraform {
  required_version = ">= 1.5.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.30.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 4.20.0"
    }
  }
}

