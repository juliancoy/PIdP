#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <image-ref-or-digest> [repo-path]"
  echo "Example: $0 ghcr.io/juliancoy/pidp@sha256:..."
  exit 1
fi

IMAGE_REF="$1"
REPO_PATH="${2:-$(pwd)}"
LOCK_FILE="/tmp/pidp-deploy.lock"

echo "Starting PIdP deploy"
echo "  image: ${IMAGE_REF}"
echo "  repo:  ${REPO_PATH}"

mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "Another deploy is already running. Exiting."
  exit 1
fi

cd "$REPO_PATH"

git fetch --all --prune
git pull --ff-only

export PIDP_PROD_IMAGE="$IMAGE_REF"
python run.py

echo "PIdP deploy complete"
