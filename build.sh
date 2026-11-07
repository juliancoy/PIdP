#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ "${1:-}" == --metadata ]]; then
  exec node serverless/scripts/build-metadata.mjs
fi
exec "${PYTHON:-python3}" scripts/build_genomic_scope.py "$@"
