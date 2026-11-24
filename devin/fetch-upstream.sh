#!/usr/bin/env bash
# Fetch the upstream agentic-attack-detections repo as a tarball (tracks
# upstream main HEAD) and sync it into this directory, alongside devin/.
# Our tooling lives in devin/; everything else here is upstream content and
# is git-ignored — do not edit it directly.
#
# Usage: ./fetch-upstream.sh [ref]   # ref defaults to main HEAD
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="ThreatDefence/agentic-attack-detections"
REF="${1:-main}"
URL="https://github.com/${REPO}/archive/refs/heads/${REF}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "== fetching $URL"
curl -fsSL "$URL" -o "$tmp/upstream.tar.gz"
tar -xzf "$tmp/upstream.tar.gz" -C "$tmp"
src="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -1)"

# sync upstream content into HERE; preserve our devin/, .venv and .gitignore
rsync -a --delete \
    --exclude='.venv/' \
    --exclude='devin/' \
    --exclude='.gitignore' \
    "$src/" "$HERE/"

echo "== upstream synced -> $HERE"
