#!/usr/bin/env bash
# Run retrohunt.py against the last HOURS of Suricata EVE exports and, when
# hits > 0, ingest them as JSON records into the OpenObserve
# `agentic_detections` stream. An OpenObserve alert on that stream (email
# destination) turns hits into a notification. Records carry the event
# timestamp so the alert only fires on fresh hits, not re-scanned history.
# Runs as the kim user via systemd --user; creds come from the
# observability .env.
#
# Usage: ./o2-ingest.sh [hours] [eve_ips] [eve_ids]
set -euo pipefail

DEVIN_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEVIN_DIR/.." && pwd)"
ENV_FILE="${O2_ENV:-/var/home/kim/workspace/v2.home-security.uk/observability/.env}"
O2_BASE="${O2_BASE:-http://localhost:5080}"
O2_ORG="${O2_ORG:-default}"
STREAM="${O2_STREAM:-agentic_detections}"
HOURS="${1:-24}"
EVE_IPS="${2:-/var/log/suricata-export/eve.json}"
EVE_IDS="${3:-/var/log/suricata-ids-export/eve.json}"

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
: "${O2_USER:?O2_USER not set in $ENV_FILE}"
: "${O2_PASS:?O2_PASS not set in $ENV_FILE}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
hits_jsonl="$work/hits.jsonl"

# Exports are multi-day append-only files. Pre-slice to the dates covering
# the window (grep is ~10x cheaper than parsing every JSON line), then let
# retrohunt's --hours do the precise cutoff.
d1="$(date -u -d "-$HOURS hours" +%F)"
d2="$(date -u +%F)"
pat="^\{\"timestamp\":\"($d1|$d2)"
touch "$work/eve-ips.jsonl" "$work/eve-ids.jsonl"
for pair in "ips:$EVE_IPS" "ids:$EVE_IDS"; do
  tag="${pair%%:*}"; src="${pair#*:}"
  [ -f "$src" ] || continue
  grep -E "$pat" "$src" > "$work/eve-$tag.jsonl" || true
done

echo "== retrohunt last ${HOURS}h $(date -Is) ==" >&2
python3 "$DEVIN_DIR/retrohunt.py" \
  --eve "$work/eve-ips.jsonl" --eve "$work/eve-ids.jsonl" \
  --hours "$HOURS" \
  --rules "$REPO_ROOT" \
  --json "$hits_jsonl" 2>&1 | tail -40

n_hits="$(wc -l < "$hits_jsonl" | tr -d ' ')"
echo "hits: $n_hits" >&2
[ "$n_hits" -eq 0 ] && exit 0

# _json endpoint accepts a JSON array. _timestamp = ingest time so the whole
# daily batch lands inside a short alert window; event time stays in `ts`.
python3 - "$hits_jsonl" "$work/payload.json" <<'PY'
import json, sys, time

now_us = int(time.time() * 1_000_000)
recs = []
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    r = json.loads(line)
    r["_timestamp"] = now_us
    recs.append(r)
json.dump(recs, open(sys.argv[2], "w"))
PY

code="$(curl -sS -o "$work/resp.txt" -w '%{http_code}' \
  -u "$O2_USER:$O2_PASS" \
  -X POST "$O2_BASE/api/$O2_ORG/$STREAM/_json" \
  -H 'Content-Type: application/json' \
  --data-binary @"$work/payload.json")"

if [ "$code" -ge 200 ] && [ "$code" -lt 300 ]; then
  echo "ingested $n_hits hits into $STREAM (HTTP $code)" >&2
else
  echo "ERROR: ingest failed HTTP $code: $(cat "$work/resp.txt")" >&2
  exit 1
fi
