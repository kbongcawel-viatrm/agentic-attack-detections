#!/usr/bin/env bash
# Local equivalent of the agentic-attack-detections GitHub workflow
# (.github/workflows/validate.yml) plus an optional retro-hunt against our
# own Suricata data. No GitHub involved.
#
# Usage:
#   ./check.sh                  # repo validation only (CI equivalent)
#   ./check.sh --hunt 24        # validation + retrohunt last 24h from OpenObserve
#   ./check.sh --hunt-eve       # validation + retrohunt on live eve.json volumes
set -euo pipefail

# rules repo = parent of this script's devin/ dir (vendored copy, not a clone)
DETECTIONS_REPO="${DETECTIONS_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
RETROHUNT="$(cd "$(dirname "$0")" && pwd)/retrohunt.py"
HOURS=24
MODE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --hunt)      MODE="o2"; HOURS="${2:-24}"; shift 2 ;;
        --hunt-eve)  MODE="eve"; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

echo "== repo: $DETECTIONS_REPO"
cd "$DETECTIONS_REPO"

# reuse the venv created during the initial local CI run; create if missing
if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
    .venv/bin/pip install -q -r tools/requirements.txt || \
        .venv/bin/pip install -q $(grep -v yara-python tools/requirements.txt)
fi
. .venv/bin/activate

echo "== validate.py"
python3 tools/validate.py

# snapshot generated/ before convert so we can detect stale artifacts
# without relying on git (upstream content is a tarball extract, not a clone)
GEN_SNAP="$(mktemp -d)"
cp -a generated/. "$GEN_SNAP/"

echo "== convert.py"
python3 tools/convert.py

echo "== generated/ freshness"
if ! diff -r "$GEN_SNAP" generated/ >/dev/null; then
    diff -r "$GEN_SNAP" generated/ | head -20 >&2
    rm -rf "$GEN_SNAP"
    echo "FAIL: generated/ is stale upstream" >&2
    exit 1
fi
rm -rf "$GEN_SNAP"

if [ "$MODE" = "o2" ]; then
    echo "== retrohunt (OpenObserve, last ${HOURS}h)"
    python3 "$RETROHUNT" --o2 --hours "$HOURS"
elif [ "$MODE" = "eve" ]; then
    echo "== retrohunt (live eve.json)"
    python3 "$RETROHUNT" \
        --eve /var/lib/containers/storage/volumes/suricata-ids-logs/_data/eve.json \
        --eve /var/lib/containers/storage/volumes/suricata-logs/_data/eve.json
fi

echo "== ALL CHECKS PASSED"
