#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend"
DEV_TEMPLATES="$FRONTEND_DIR/templates"
DEV_ASSETS="$FRONTEND_DIR/assets"
STABLE_DIR="$FRONTEND_DIR/stable"
STABLE_TEMPLATES="$STABLE_DIR/templates"
STABLE_ASSETS="$STABLE_DIR/assets"
BACKUP_ROOT="$FRONTEND_DIR/.stable-backups"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/$STAMP"

mkdir -p "$STABLE_DIR" "$BACKUP_ROOT"

if [[ -d "$STABLE_TEMPLATES" || -d "$STABLE_ASSETS" ]]; then
  mkdir -p "$BACKUP_DIR"
  [[ -d "$STABLE_TEMPLATES" ]] && cp -R "$STABLE_TEMPLATES" "$BACKUP_DIR/templates"
  [[ -d "$STABLE_ASSETS" ]] && cp -R "$STABLE_ASSETS" "$BACKUP_DIR/assets"
  echo "Backed up previous stable snapshot to: $BACKUP_DIR"
fi

rm -rf "$STABLE_TEMPLATES" "$STABLE_ASSETS"
cp -R "$DEV_TEMPLATES" "$STABLE_TEMPLATES"
cp -R "$DEV_ASSETS" "$STABLE_ASSETS"

echo "Promoted frontend dev -> stable"
echo "Stable templates: $STABLE_TEMPLATES"
echo "Stable assets:    $STABLE_ASSETS"
