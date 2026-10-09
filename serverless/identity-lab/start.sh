#!/usr/bin/env bash
set -euo pipefail
lab_root="$(cd "$(dirname "$0")/../.." && pwd)"
lab_state="$lab_root/.local/identity-lab"
mkdir -p "$lab_state"
chmod 700 "$lab_state"
if [[ ! -f "$lab_state/key.pem" ]] || ! openssl x509 -in "$lab_state/cert.pem" -noout -checkhost pidp.identity.test >/dev/null 2>&1; then
 openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout "$lab_state/key.pem" -out "$lab_state/cert.pem" -subj '/CN=pidp.identity.test' -addext 'subjectAltName=DNS:pidp.identity.test,DNS:lifetech.identity.test,DNS:orgportal.identity.test,DNS:medtech.identity.test' >/dev/null 2>&1
fi
if ! docker network inspect pidp-identity-lab >/dev/null 2>&1; then docker network create --internal pidp-identity-lab >/dev/null; fi
if docker container inspect pidp-identity-lab >/dev/null 2>&1; then docker rm -f pidp-identity-lab >/dev/null; fi
docker run -d --name pidp-identity-lab --network pidp-identity-lab --read-only --tmpfs /tmp --volume "$lab_root/serverless/src:/workspace/serverless/src:ro" --volume "$lab_root/serverless/migrations:/workspace/serverless/migrations:ro" --volume "$lab_root/serverless/node_modules:/workspace/serverless/node_modules:ro" --volume "$lab_root/serverless/identity-lab:/workspace/serverless/identity-lab:ro" --volume "$lab_root/serverless/package.json:/workspace/serverless/package.json:ro" --volume "$lab_root/shared:/workspace/shared:ro" --volume "$lab_state:/certs:ro" --workdir /workspace/serverless node:24-alpine node --import tsx identity-lab/server.mjs

cat > "$lab_state/gateway.conf" <<'NGINX'
events {}
stream { server { listen 8443; proxy_pass pidp-identity-lab:8443; } }
NGINX
if docker container inspect pidp-identity-lab-gateway >/dev/null 2>&1; then docker rm -f pidp-identity-lab-gateway >/dev/null; fi
docker create --name pidp-identity-lab-gateway --network bridge --publish 127.0.0.1:8891:8443 --volume "$lab_state/gateway.conf:/etc/nginx/nginx.conf:ro" nginx:alpine >/dev/null
docker network connect pidp-identity-lab pidp-identity-lab-gateway
docker start pidp-identity-lab-gateway >/dev/null

for attempt in $(seq 1 30); do
 if docker exec pidp-identity-lab wget --no-check-certificate -qO- https://127.0.0.1:8443/health >/dev/null 2>&1; then
  echo 'Identity lab: https://pidp.identity.test:8891 (local test accounts only)'
  exit 0
 fi
 sleep 1
done
echo 'Identity lab did not become ready' >&2
exit 1
