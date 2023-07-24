---
version: "3.9"
name: terraform-enterprise
services:
  tfe:
    image: quay.io/hashicorp/terraform-enterprise:${tfe_quaiio_tag}
    environment:
      TFE_HOSTNAME: ${hostname}
      TFE_OPERATIONAL_MODE: "external"    
      TFE_ENCRYPTION_PASSWORD: ${enc_password}
      TFE_DISK_CACHE_VOLUME_NAME: terraform-enterprise-cache
      TFE_TLS_CERT_FILE: /var/lib/tfe/certificate.pem
      TFE_TLS_KEY_FILE: /var/lib/tfe/key.pem
      TFE_TLS_CA_BUNDLE_FILE: /var/lib/tfe/chain.pem
      TFE_TLS_VERSION: tls_1_3
      TFE_DATABASE_USER: ${pg_password}
      TFE_DATABASE_PASSWORD: ${pg_user}
      TFE_DATABASE_HOST: ${pg_netloc}
      TFE_DATABASE_NAME: ${pg_dbname}
      TFE_DATABASE_PARAMETERS: sslmode=require
      TFE_OBJECT_STORAGE_TYPE: "s3"
      TFE_OBJECT_STORAGE_S3_USE_INSTANCE_PROFILE: true
      TFE_OBJECT_STORAGE_S3_REGION: ${region}
      TFE_OBJECT_STORAGE_S3_BUCKET: ${s3_bucket}
      TFE_OBJECT_STORAGE_S3_SERVER_SIDE_ENCRYPTION: AES256
      TFE_LICENSE_PATH: /etc/tfe-license.rli
      TFE_REDIS_PASSWORD: ${redis_pass}
      TFE_REDIS_USE_TLS: false
      TFE_REDIS_USE_AUTH: false
      TFE_IACT_SUBNETS: "0.0.0.0/0"
      TFE_IACT_TIME_LIMIT: "unlimited"
      TFE_METRICS_ENABLE: true
      TFE_NODE_ID: ${install_id}
      TFE_TLS_ENFORCE: true
    cap_add:
      - IPC_LOCK
    read_only: true
    tmpfs:
      - /tmp
      - /run
      - /var/log/terraform-enterprise
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /run/docker.sock
      - type: bind
        source: ./certs
        target: /etc/ssl/private/terraform-enterprise
      - type: volume
        source: terraform-enterprise-cache
        target: /var/cache/tfe-task-worker/terraform
volumes:
  terraform-enterprise-cache:
