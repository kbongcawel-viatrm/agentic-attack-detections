#!/usr/bin/env bash
# Hourly/daily Suricata assessment: collect stats -> assess -> Markdown report.
#
# Usage:
#   ./daily_assess.sh [output_dir] [--hours N] [--arp-journal|--arp-log FILE]
#                     [--o2-report] [--llm]
#   default output_dir: suricata-analyzer/output/ in the project repo
#
# Decision architecture:
#   collect_stats.py -> stats.json
#   --llm (optional) -> Ollama emits structured FINDINGS (JSON, class A-D +
#                       evidence). The model never decides the verdict.
#   assess.py        -> deterministic criteria -> score -> verdict band
#                       (ACTION REQUIRED / MONITOR / NO ACTION / NO DATA)
#   render_text.py   -> Markdown artifact
#
# Env:
#   O2_HOST O2_ORG O2_USER O2_PASS   OpenObserve connection (required for stats)
#   CF_STATE_FILE                     cf-block state path (optional)
#   OLLAMA_HOST                       default http://localhost:11434
#   OLLAMA_MODEL                      default suricata-analyst
#   LLM_TIMEOUT                       seconds for the model call (default 900)
#
# Cron/timer examples (log pulls refresh hourly):
#   hourly: 7 * * * * .../daily_assess.sh --hours 1 --arp-log /var/log/arpwatch-export/arpwatch.log --o2-report >> /var/log/suricata-reports/cron.log 2>&1
#   daily:  15 6 * * * .../daily_assess.sh --hours 24 --o2-report >> /var/log/suricata-reports/cron.log 2>&1
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$SKILL_DIR/scripts"
OUT_DIR=""
if [[ $# -gt 0 && "$1" != --* ]]; then OUT_DIR="$1"; shift; fi
HOURS=24; ARP=0; O2_REPORT=0; USE_LLM=0; CF_SUBMIT=0; EMAIL=0
ARP_LOG_FILE="${ARP_LOG_FILE:-/var/log/arpwatch-export/arpwatch.log}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hours) HOURS="$2"; shift 2;;
    --arp-journal) ARP=1; shift;;
    --arp-log) ARP_LOG_FILE="$2"; shift 2;;
    --o2-report) O2_REPORT=1; shift;;
    --email) EMAIL=1; shift;;
    --llm) USE_LLM=1; shift;;
    --cf-submit) CF_SUBMIT=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

STAMP="$(date +%F-%H%M)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# Default artifact location: suricata-analyzer/output/ in the project repo
OUT_DIR="${OUT_DIR:-/var/home/kim/workspace/v2.home-security.uk/v2.home-security.uk/suricata-analyzer/output}"
mkdir -p "$OUT_DIR"

export O2_HOST="${O2_HOST:-http://localhost:5080}"
export O2_ORG="${O2_ORG:-default}"
: "${O2_USER:?set O2_USER}"; : "${O2_PASS:?set O2_PASS}"
export O2_USER O2_PASS

OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
MODEL="${OLLAMA_MODEL:-suricata-analyst}"
LLM_TIMEOUT="${LLM_TIMEOUT:-900}"

echo "[$(date -Is)] collecting stats (last ${HOURS}h) -> $WORK/stats.json"
ARP_ARG=(); [[ $ARP -eq 1 ]] && ARP_ARG+=(--arp-journal)
[[ -n "$ARP_LOG_FILE" && -f "$ARP_LOG_FILE" ]] && ARP_ARG+=(--arp-log "$ARP_LOG_FILE")
python3 "$SCRIPTS/collect_stats.py" --hours "$HOURS" --out "$WORK/stats.json" "${ARP_ARG[@]}"

FINDINGS="$WORK/findings.json"
if [[ $USE_LLM -eq 1 ]]; then
  echo "[$(date -Is)] requesting findings from $MODEL (timeout ${LLM_TIMEOUT}s)"
  # Trim stats if huge: keep top-N lists small enough for the model's context.
  python3 - "$WORK/stats.json" "$WORK/prompt.txt" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
for k in ("top_src_ips", "top_dst_ips"):
    s[k] = s[k][:15]
for k in s["alerts"]:
    s["alerts"][k] = s["alerts"][k][:10]
s["dns_top"] = s["dns_top"][:10]
for sect in s["enrichment"].values():
    for k in ("submitted_ips", "malicious_flagged_ips", "pending_action_ips", "alert_src_ips"):
        if k in sect: sect[k] = sect[k][:30]
    if "top_ips" in sect: sect["top_ips"] = sect["top_ips"][:15]
prompt = (
    "You are a network-security analyst. Below are aggregated Suricata "
    "statistics (JSON). Report OBSERVATIONS ONLY — do not decide any "
    "verdict, score, or action.\n\n"
    "Data:\n```json\n" + json.dumps(s, indent=1) + "\n```\n\n"
    "Output ONLY a JSON object (no markdown fences, no prose) with this "
    "exact shape:\n"
    '{"findings": [{"ip": "<ip>", "class": "A|B|C|D", '
    '"behavior": "<short label>", "evidence": "<what in the data supports it>"}], '
    '"narrative": "<2-4 sentence summary of what you observed>"}\n\n'
    "Classes: A = strong malicious indicator (C2, exfil, exploit), "
    "B = suspicious pattern needing review, C = likely benign / known "
    "noise, D = insufficient evidence. Only report IPs that appear in the "
    "data. Prefer fewer, well-evidenced findings over many guesses. "
    "If nothing is notable, return {\"findings\": [], \"narrative\": \"...\"}."
)
open(sys.argv[2], "w").write(prompt)
PY
  if timeout "$LLM_TIMEOUT" ollama run "$MODEL" "$(cat "$WORK/prompt.txt")" \
       > "$WORK/findings_raw.txt" 2>"$WORK/ollama.err"; then
    # extract JSON: strip fences, then take the outermost {...} block
    # (failure is non-fatal — we just assess without LLM findings)
    python3 - "$WORK/findings_raw.txt" "$FINDINGS" <<'PY' || true
import json, re, sys
raw = open(sys.argv[1]).read()
m = re.search(r"\{.*\}", raw, flags=re.S)
if not m:
    sys.exit("no JSON object in model output")
obj = json.loads(m.group(0))
if not isinstance(obj.get("findings"), list):
    obj["findings"] = []
json.dump(obj, open(sys.argv[2], "w"), indent=2)
PY
    if [[ -s "$FINDINGS" ]]; then
      echo "[$(date -Is)] LLM findings accepted -> $FINDINGS"
    else
      echo "[$(date -Is)] LLM output had no usable findings — assessing without them" >&2
      rm -f "$FINDINGS"
    fi
  else
    echo "[$(date -Is)] LLM call failed/timeout — assessing without findings" >&2
    tail -5 "$WORK/ollama.err" >&2 || true
    rm -f "$FINDINGS"
  fi
fi

echo "[$(date -Is)] assessing (deterministic criteria)"
# subject memory is per-window-size: hourly and daily streaks are separate
STATE_FILE="$OUT_DIR/assessment-state-${HOURS}h.json"
ASSESS_ARGS=(--stats "$WORK/stats.json" --assessment "$WORK/assessment.json"
             --verdict "$WORK/verdict.md" --state "$STATE_FILE")
[[ -f "$FINDINGS" ]] && ASSESS_ARGS+=(--findings "$FINDINGS")
python3 "$SCRIPTS/assess.py" "${ASSESS_ARGS[@]}"

# High-confidence + agentic-corroborated subjects are Cloudflare candidates.
# --cf-submit pushes them to the block list (manual gate; needs cf.env sourced).
CF_CANDIDATES=$(python3 - "$WORK/assessment.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
print(" ".join(s["subject"] for s in a.get("subjects", []) if s.get("cf_candidate")))
PY
)
if [[ -n "$CF_CANDIDATES" ]]; then
  echo "[$(date -Is)] Cloudflare candidates: $CF_CANDIDATES"
  if [[ $CF_SUBMIT -eq 1 ]]; then
    set -a; [[ -f /var/home/kim/workspace/suricata-cf/cf.env ]] && . /var/home/kim/workspace/suricata-cf/cf.env; set +a
    python3 "$SCRIPTS/cf_submit.py" --assessment "$WORK/assessment.json" \
      || echo "[$(date -Is)] cf_submit failed (non-fatal)" >&2
  else
    echo "[$(date -Is)] (pass --cf-submit to push candidates to Cloudflare)"
  fi
fi

echo "[$(date -Is)] rendering report"
REPORT="$OUT_DIR/suricata-assessment-$STAMP.md"
python3 "$SCRIPTS/render_text.py" --stats "$WORK/stats.json" \
  --verdict "$WORK/verdict.md" --out "$REPORT"

if [[ $O2_REPORT -eq 1 ]]; then
  python3 - "$WORK/assessment.json" "$WORK/stats.json" <<'PY'
import json, os, sys, urllib.request, base64
a = json.load(open(sys.argv[1]))
stats = json.load(open(sys.argv[2]))
rec = {
    "report_date": stats["meta"]["window_end"],
    "window_hours": stats["meta"]["window_hours"],
    "total_events": a["context"]["total_events"],
    "alert_count": a["context"]["alerts_ex_noise"],
    "flagged_ips": a["context"]["flagged_ips"],
    "pending_cf_action": a["context"]["cf_pending"],
    "cf_submitted": a["context"]["cf_submitted"],
    "arp_suspicious": a["context"]["arp_suspicious_window"],
    "verdict": a["verdict"],
    "confidence": a["confidence"],
    "subjects_assessed": len(a.get("subjects", [])),
    "worst_subjects": [
        {"subject": s["subject"], "conclusion": s["conclusion"]}
        for s in a.get("subjects", [])
        if s["conclusion"] in ("HOSTILE", "SUSPICIOUS")][:10],
    "cf_candidates": [s["subject"] for s in a.get("subjects", [])
                      if s.get("cf_candidate")],
}
base = os.environ["O2_HOST"].rstrip("/"); org = os.environ.get("O2_ORG", "default")
auth = base64.b64encode(f'{os.environ["O2_USER"]}:{os.environ["O2_PASS"]}'.encode()).decode()
url = f"{base}/api/{org}/suricata_reports/_json"
req = urllib.request.Request(url, data=json.dumps([rec]).encode(), method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("Authorization", "Basic " + auth)
print(urllib.request.urlopen(req, timeout=30).read()[:200])
PY
fi

if [[ $EMAIL -eq 1 ]]; then
  MAIL_ENV="${MAIL_ENV:-$HOME/.config/suricata-assess/mail.env}"
  if [[ -f "$MAIL_ENV" ]]; then
    python3 - "$WORK/assessment.json" "$REPORT" "$HOURS" "$MAIL_ENV" <<'PY'
import json, sys, os, smtplib, html
from email.message import EmailMessage
from email.utils import formatdate

a = json.load(open(sys.argv[1]))
report_path, hours, env_path = sys.argv[2], sys.argv[3], sys.argv[4]
env = {}
for line in open(env_path):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")

ctx = a.get("context", {})
verdict = a.get("verdict", "?")
confidence = a.get("confidence", "?")
color = {"CLEAN": "#16a34a", "ANOMALOUS": "#dc2626", "INCONCLUSIVE": "#d97706"}.get(verdict, "#64748b")
subjects = "".join(
    f'<tr><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{html.escape(s["subject"])}</td>'
    f'<td style="padding:6px 10px;border-bottom:1px solid #1e293b;color:{ "#dc2626" if s["conclusion"]=="HOSTILE" else "#d97706" if s["conclusion"]=="SUSPICIOUS" else "#94a3b8"};">{html.escape(s["conclusion"])}</td></tr>'
    for s in a.get("subjects", [])[:10])

body = f"""<!DOCTYPE html><html><body style="margin:0;background:#0b1120;font-family:Arial,sans-serif;">
<div style="max-width:640px;margin:0 auto;background:#0f172a;border:1px solid #1e293b;border-radius:10px;overflow:hidden;">
<div style="background:linear-gradient(135deg,#0ea5e9,#6366f1);padding:18px 24px;color:#fff;">
<div style="font-size:18px;font-weight:bold;letter-spacing:1px;">SURICATA TRAFFIC REPORT</div>
<div style="font-size:12px;color:#bae6fd;">last {html.escape(hours)}h &middot; {html.escape(str(ctx.get('total_events','')))} events</div></div>
<div style="padding:20px 24px;color:#e2e8f0;font-size:14px;">
<div style="display:inline-block;background:{color};color:#fff;font-weight:bold;padding:5px 14px;border-radius:20px;margin-bottom:14px;">{html.escape(verdict)} &middot; {html.escape(confidence)} confidence</div>
<table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:14px;">
<tr><td style="padding:6px 10px;color:#64748b;border-bottom:1px solid #1e293b;">Suricata alerts</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{ctx.get('alerts_ex_noise','')}</td></tr>
<tr><td style="padding:6px 10px;color:#64748b;border-bottom:1px solid #1e293b;">Flagged IPs</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{ctx.get('flagged_ips','')}</td></tr>
<tr><td style="padding:6px 10px;color:#64748b;border-bottom:1px solid #1e293b;">Pending CF action</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{ctx.get('cf_pending','')}</td></tr>
<tr><td style="padding:6px 10px;color:#64748b;border-bottom:1px solid #1e293b;">CF submitted</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{ctx.get('cf_submitted','')}</td></tr>
<tr><td style="padding:6px 10px;color:#64748b;border-bottom:1px solid #1e293b;">ARP suspicious</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{ctx.get('arp_suspicious_window','')}</td></tr>
</table>
{'<h3 style="font-size:14px;margin:0 0 8px;">Subjects</h3><table style="width:100%;border-collapse:collapse;font-size:12px;">' + subjects + '</table>' if subjects else ''}
<p style="color:#64748b;font-size:11px;margin-top:16px;">Full markdown report attached. Generated {html.escape(formatdate(localtime=True))}.</p>
</div></div></body></html>"""

msg = EmailMessage()
msg["Subject"] = f"ThreatDefense Report [{verdict}] — last {hours}h"
msg["From"] = env.get("SMTP_FROM_EMAIL") or env.get("SMTP_USER_NAME")
msg["To"] = env.get("SMTP_USER_NAME")
msg.set_content("Suricata assessment report attached (HTML version not shown in plain-text clients).")
msg.add_alternative(body, subtype="html")
with open(report_path, "rb") as f:
    msg.add_attachment(f.read(), maintype="text", subtype="markdown",
                       filename=os.path.basename(report_path))

host, port = env.get("SMTP_HOST", "smtp.gmail.com"), int(env.get("SMTP_PORT", "587"))
enc = env.get("SMTP_ENCRYPTION", "starttls").lower()
with smtplib.SMTP(host, port, timeout=30) as s:
    s.ehlo()
    if enc == "starttls":
        s.starttls(); s.ehlo()
    elif enc == "ssl":
        s = smtplib.SMTP_SSL(host, port, timeout=30)
    s.login(env["SMTP_USER_NAME"], env["SMTP_PASSWORD"])
    s.send_message(msg)
print("email sent:", msg["Subject"])
PY
  else
    echo "[$(date -Is)] --email set but $MAIL_ENV missing" >&2
  fi
fi

echo "[$(date -Is)] done -> $REPORT"
