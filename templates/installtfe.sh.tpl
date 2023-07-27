#!/usr/bin/env bash

# Stop on any error
set -euo pipefail

function get_secret {
    local secret_id=$1
    /usr/bin/env aws secretsmanager get-secret-value --secret-id $secret_id --region ${region} | jq --raw-output '.SecretBinary,.SecretString | select(. != null)'
}

logpath="/home/ubuntu/install/tfeinstall.log" 

mkdir -p /var/lib/tfe

mkdir -p /home/ubuntu/install

ipaddr=$(hostname -I | awk '{print $1}')

echo "$(date +"%T_%F") Create TFE and replicated setting files" | tee -a $logpath

echo "$(date +"%T_%F") Create docker config" | tee -a $logpath

sudo mkdir -p /etc/docker | tee -a $logpath

sudo echo "${docker_config}" | sudo base64 --decode > /etc/docker/daemon.json

echo "$(date +"%T_%F") Start and enable docker" | tee -a $logpath

sudo systemctl start docker

sleep 10

sudo systemctl enable docker

echo "$(date +"%T_%F") Extract certificate, key, license from AWS Secretsmanager" | tee -a $logpath

cert_base64=$(get_secret ${cert_secret_id})

key_base64=$(get_secret ${key_secret_id})

chain_base64=$(get_secret ${chain_secret_id})

license_base64=$(get_secret ${license_secret_id})

echo "$(date +"%T_%F") Write tls certificate" | tee -a $logpath

echo $cert_base64 | base64 --decode > /var/lib/tfe/certificate.pem

echo "$(date +"%T_%F") Write tls key" | tee -a $logpath

echo $key_base64 | base64 --decode > /var/lib/tfe/key.pem

sudo chmod 600 /var/lib/tfe/key.pem

echo "$(date +"%T_%F") Write tls chain" | tee -a $logpath

echo $chain_base64 | base64 --decode > /var/lib/tfe/chain.pem

echo "$(date +"%T_%F") Write license" | tee -a $logpath

sudo echo $license_base64 | sudo base64 --decode > /var/lib/tfe/tfe-license.lic

echo "$(date +"%T_%F") Write docker compose config" | tee -a $logpath

sudo echo "${docker_compose_config}" | sudo base64 --decode > /home/ubuntu/install/docker_compose.yml

echo "$(date +"%T_%F") Docker login to quai.io" | tee -a $logpath

sudo docker login -u="${docker_quaiio_login}" -p="${docker_quaiio_token}" quay.io  | tee -a $logpath

echo "$(date +"%T_%F") Docker pull image from quai.io" | tee -a $logpath

sudo docker pull quay.io/hashicorp/terraform-enterprise:${tfe_quaiio_tag}  | tee -a $logpath

cd /home/ubuntu/install

sudo mkdir -p /var/log/tfe

sudo apt-mark hold docker docker-ce docker-compose-plugin docker-ce-rootless-extras docker-ce-cli docker-buildx-plugin

echo "$(date +"%T_%F") Starting docker compose" | tee -a $logpath

sudo docker compose -f /home/ubuntu/install/docker_compose.yml up -d
