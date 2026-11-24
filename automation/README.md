# Home ThreatDefense automation

Operational automation for the home Suricata IDS/IPS deployment
(`suricata-containerized-rootful`). Everything here runs on the host as the
`kim` user via systemd **user** units, except the `*-update-rules` pair which
runs as **root** system units.

## Layout

| Path | Contents |
|---|---|
| `devin/` | Agentic-detection tooling: `retrohunt.py` (signature retrohunt over EVE JSON, `--json`/`--hours`), `o2-ingest.sh` (retrohunt → OpenObserve `agentic_detections` stream), `pack-logs.sh` (daily EVE export pack → `eve-logs` orphan branch for GitHub scan), `check.sh`, `fetch-upstream.sh` |
| `suricata-trend-report/` | Copy of the `suricata-trend-report` skill: hourly/daily traffic assessment (`ollama/daily_assess.sh` + `scripts/`). `--email` sends an HTML report + markdown attachment via SMTP |
| `automation/systemd/` | All systemd unit files (user + root). Canonical live copies: `~/.config/systemd/user/` and `/etc/systemd/system/` |
| `openobserve/` | Exported O2 config: `alerts.json`, `destination-ThreatDefense.json`, `template-threatdefense.json`, `mail.env.example` (no secrets) |

## Pipelines

```
eve-logs-pack.timer (04:30 UTC)
  └─ packs last 24h EVE exports → eve-logs orphan branch → GH Actions scan
agentic-detections-alert.timer (05:15 UTC)
  └─ o2-ingest.sh: retrohunt --hours 24 on both EVE exports
       → hits>0 → POST agentic_detections stream
            └─ O2 alert agentic-detections-daily-hits (05:45 UTC cron)
                 └─ ThreatDefense email destination → Gmail
suricata-assess.timer (hourly) / suricata-assess-daily.timer (24h)
  └─ daily_assess.sh --o2-report --email
       ├─→ O2 suricata_reports stream (realtime_suricata_reports alert)
       └─→ direct SMTP email (HTML + .md attachment)
suricata-update-rules.timer (03:30) / agentic-rules-update.timer (04:30)  [root]
  └─ suricata-update + sync-agentic-rules.sh → /var/lib/suricata-ids/{rules,config}
       → suricata -T validate → restart suricata.service + suricata-ids.service
```

## Secrets (never committed)

- `~/.config/suricata-assess/mail.env` — SMTP creds (mode 600); template in
  `openobserve/mail.env.example`
- `observability/.env` in `v2.home-security.uk` — `O2_USER`/`O2_PASS`
- `suricata-cf/cf.env` — Cloudflare token (cf_submit.py)

## Notes

- OpenObserve v1.1.2 alert templates cannot interpolate row fields into email
  bodies — that is why `daily_assess.sh --email` sends mail directly. The O2
  `realtime_suricata_reports` alert is kept as a lightweight trigger only.
- The `agentic-attack-detections` submodule in `suricata-containerized-rootful`
  intentionally tracks upstream `ThreatDefence/agentic-attack-detections`; this
  repo holds only the local automation layered on top.
