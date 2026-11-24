#!/usr/bin/env bash
# Package the last N hours of Suricata EVE exports and force-push them to the
# `eve-logs` orphan branch of this repo, so the GitHub-hosted daily workflow
# (ubuntu-latest) can scan them without a self-hosted runner.
#
# Each run creates a fresh single-commit orphan branch — no clone needed.
#
# Usage: ./pack-logs.sh [hours]        # default 24
#        EVE_IPS=... EVE_IDS=... ./pack-logs.sh
#        PACK_DRY_RUN=1 ./pack-logs.sh  # build tarball, skip push
set -euo pipefail

HOURS="${1:-24}"
EVE_IPS="${EVE_IPS:-/var/log/suricata-export/eve.json}"
EVE_IDS="${EVE_IDS:-/var/log/suricata-ids-export/eve.json}"
MAIN_REPO="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE="$(git -C "$MAIN_REPO" remote get-url origin)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/work"

EVE_IPS="$EVE_IPS" EVE_IDS="$EVE_IDS" HOURS="$HOURS" WORK="$tmp/work" python3 - <<'PY'
import json, os
from datetime import datetime, timedelta, timezone

hours = float(os.environ["HOURS"])
work = os.environ["WORK"]
cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
for tag, path in (("ips", os.environ["EVE_IPS"]), ("ids", os.environ["EVE_IDS"])):
    out = os.path.join(work, f"eve-{tag}-{hours:g}h.jsonl")
    kept = 0
    with open(path) as f, open(out, "w") as g:
        for line in f:
            try:
                ts = datetime.fromisoformat(json.loads(line).get("timestamp", ""))
            except Exception:
                continue
            if ts >= cutoff:
                kept += 1
                g.write(line if line.endswith("\n") else line + "\n")
    print(f"{tag}: kept {kept} events (last {hours:g}h) -> {out}")
PY

(cd "$tmp/work" && tar -czf "$tmp/eve-logs.tar.gz" eve-ips-*.jsonl eve-ids-*.jsonl)
ls -lh "$tmp/eve-logs.tar.gz"

if [ "${PACK_DRY_RUN:-0}" = "1" ]; then
    echo "PACK_DRY_RUN=1 — tarball at $tmp/eve-logs.tar.gz (not pushed)"
    cp "$tmp/eve-logs.tar.gz" /tmp/eve-logs-dryrun.tar.gz
    exit 0
fi

git -C "$tmp" init -q -b eve-logs repo
mv "$tmp/eve-logs.tar.gz" "$tmp/repo/"
workspaceconnect github-automation
git -C "$tmp/repo" add -A
git -C "$tmp/repo" -c user.name="eve-logs-bot" \
    -c user.email="eve-logs-bot@users.noreply.github.com" \
    commit -qm "eve logs $(date -u +%Y-%m-%dT%H:%M:%SZ) — last ${HOURS}h"
git -C "$tmp/repo" push -f "$REMOTE" HEAD:refs/heads/eve-logs

echo "pushed eve-logs branch -> $REMOTE"
