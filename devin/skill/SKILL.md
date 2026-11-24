---
name: agentic-attack-detections
description: Use when working with the ThreatDefence agentic-attack-detections repository (fetched tarball at ~/workspace/suricata-containerized-rootful/agentic-attack-detections/ (upstream content git-ignored; devin/fetch-upstream.sh pulls ThreatDefence main HEAD)) — detection rules, hunting queries, IOCs and feeds for AI-agent attack frameworks (ARTEX/AntiFox, Cairn, PentAGI, HexStrike, CyberStrikeAI, Strix, Hermes Agent, Agent Zero) plus cross-framework "behaviors". Covers validating the repo (tools/validate.py, tools/convert.py), retro-hunting the Suricata rules against our own EVE JSON / OpenObserve data with suricata-containerized-rootful/agentic-attack-detections/devin/retrohunt.py, and deploying rules to Sentinel/Suricata/Zeek/YARA/Splunk/Elastic. Trigger on "agentic attack detections", "ARTEX detections", "Cairn/PentAGI/HexStrike/Strix detections", or when asked to test these rules against our Suricata logs.
---

# Agentic Attack Detections (ThreatDefence)

Local clone: `/var/home/kim/workspace/suricata-containerized-rootful/agentic-attack-detections/`
— upstream `github.com/ThreatDefence/agentic-attack-detections` (formerly
`artex-detections`) fetched as a tarball of `main` HEAD by `devin/fetch-upstream.sh`.
Upstream files are git-ignored; only `devin/` tooling is tracked. To pin a
ref: `devin/fetch-upstream.sh <ref>`.

Detection content for open-source **agentic attack frameworks** — tools that hand an
intrusion to AI agents which plan, run real attack tools and persist until a goal.
Everything is experimental: the README states no rule has been tested against a
captured intrusion. Baseline before alerting.

## Repository map

| Path | Contents |
|---|---|
| `iocs/indicators.csv` | **Single source of truth**: ~515 indicators (type, value, confidence, context, actor, source, reported date, review_by, framework). |
| `feeds/` | Generated from the CSV: STIX 2.1 bundle, Sentinel watchlist (`sentinel-watchlist.csv`, alias `AGENTIC_IOCs`), plain lists (ipv4/ipv6/domains/urls/user_agents/md5/sha256), `by-framework/` per-framework lists. |
| `behaviors/` | Cross-framework rules: coding-agent CLIs in auto-approve mode spawning attack tools, servers calling AI model APIs, agent page-reader UAs next to attack traffic, rotating-proxy probing, config/backup theft + WSUS probes, Kerberos enum + SMB/WinRM fan-out, callback-to-prober, AWS creds at machine speed, out-of-band testing domains (oast.*/interact.sh/burpcollaborator/dnslog.cn). Subdirs: `sentinel/`, `sigma/`, `suricata/behaviors.rules`, `zeek/agentic-behaviors/` + `zeek/tests/`. |
| `frameworks/<name>/` | One folder per framework: `agent-zero`, `artex` (incl. AntiFox fork), `cairn`, `cyberstrikeai`, `hermes`, `hexstrike`, `pentagi`, `strix`. Each has `README.md`, `source-code-signals.md`, `coverage.md`, `hunting-order.md`, `sentinel/hunting/*.kql`, `sentinel/analytics/*.yaml`, `sigma/<category>/*.yml`, `suricata/<name>.rules` (hand-written) + `<name>-ip.rules` (**generated — do not edit**), `zeek/intel/*.intel` (generated), `yara/*.yar`. ARTEX additionally has a Splunk app and Elastic rules. |
| `generated/` | Every Sigma rule converted to Splunk SPL, Sentinel ASIM KQL, Elastic ES\|QL + Lucene, split by framework/behaviors. `generated/SUMMARY.md` tracks conversion coverage. |
| `tools/` | `build_feeds.py` (CSV → feeds/ip.rules/zeek intel), `convert.py` (Sigma → generated/), `validate.py` (CI validator), `requirements.txt`. |
| `.github/workflows/validate.yml` | CI: checkout → pip install → `validate.py` → `convert.py` → fail if `generated/` diff non-empty. |

## Confidence model

- **High** — specific to a framework/campaign: alert on it.
- **Medium** — seen in framework activity but changeable/shared: alert after baselining or hunt.
- **Low** — common/legitimate (AI model APIs, agent CLI user agents, hosting ASNs, proxy providers): context for another finding only, never alert alone.
- Address IOCs carry `review_by` = reported + 180 days; cloud/VPS addresses get reassigned — check before blocking.

## Suricata rules

~94 content rules + generated IP lists across 17 `.rules` files. SID ranges per
framework (see `docs/adding-a-framework.md`): behaviors keep first-published
SIDs (9727xxx), ARTEX 9726xxx, Cairn 9727xxx, PentAGI 9728xxx, HexStrike 9729xxx,
CyberStrikeAI 9730xxx, Strix 9731xxx, Hermes 9732xxx, Agent Zero 9733xxx.

Match surfaces: `http.user_agent`, `http.uri`, `http.host`, `http.method`,
`http.request_body`, `http.response_body`, `http.header`, `http.header_names`,
`http.server`, `dns.query`, `tls.sni`, `tls.cert_subject`, `tls.cert_issuer`,
one `tcp` payload rule, one port-range rule (PentAGI workers 28000–29999),
plus `alert ip` rules for reported addresses.

**Coverage caveat:** HTTP rules need cleartext or decrypted traffic; DNS and TLS
SNI rules work on encrypted traffic. **Our sensors do not log `tls.sni`, and the
IPS eve.json carries no `dns` events** — SNI rules and (on IPS) DNS rules cannot
fire there. The IDS sensor does log DNS.

## One-command local check (no GitHub needed)

`suricata-containerized-rootful/agentic-attack-detections/devin/check.sh` replicates
the upstream workflow locally and optionally adds the retro-hunt:

```bash
check.sh                # validate.py + convert.py + generated/ diff (CI equivalent)
check.sh --hunt 24      # + retrohunt last 24h from OpenObserve
check.sh --hunt-eve     # + retrohunt on the live eve.json volumes
```

`devin/pack-logs.sh [hours]` slices the last N hours of both EVE exports into a
tarball and force-pushes it to the repo's `eve-logs` orphan branch — the feed
stock for `.github/workflows/agentic-detections-daily.yml`, which runs on
GitHub-hosted `ubuntu-latest` (no self-hosted runner). Run via cron before the
workflow's 05:23 UTC schedule; `PACK_DRY_RUN=1` builds without pushing.

## Validating / regenerating (what CI does)

```bash
cd /var/home/kim/workspace/suricata-containerized-rootful/agentic-attack-detections
python3 -m venv .venv && . .venv/bin/activate
pip install -r tools/requirements.txt   # yara-python needs Python.h — skip it if build fails; validate.py treats YARA as optional
python3 tools/validate.py                # Sigma/KQL/ES|QL/TOML/Splunk/Suricata SIDs/YARA/osquery/feeds
python3 tools/convert.py                 # regenerate generated/
git diff --exit-code generated/          # must be empty
python3 tools/build_feeds.py             # regenerate feeds/ + *-ip.rules + zeek intel from CSV
```

Last verified locally (2026-11-22, Python 3.15): validate.py all checks passed
(64 Sigma files, 69 hunts, 5 Elastic rules, 15 Splunk searches, 246 Suricata
rules, feeds up to date); convert.py wrote 204 conversions with clean diff.
`yara`/`zeek` checks skip when the tools aren't installed.

Network tests (need `suricata` and `zeek` binaries — not installed on this host):
`frameworks/artex/tests/run_network_tests.sh`, `behaviors/zeek/tests/run_tests.sh`.

## Retro-hunting our own Suricata data

Live EVE JSON (rootful podman volumes, continuously written):

- IPS: `/var/lib/containers/storage/volumes/suricata-logs/_data/eve.json` (~250 MB)
- IDS: `/var/lib/containers/storage/volumes/suricata-ids-logs/_data/eve.json` (~140 MB)

OpenObserve mirror: `http://localhost:5080`, org `default`, streams
`suricata_ips` + `suricata_ids`; creds `O2_USER`/`O2_PASS` in
`/var/home/kim/workspace/v2.home-security.uk/observability/.env`.

**Use the retro-hunt script** (canonical copy lives with the Suricata project;
a copy of this skill also sits next to it in `agentic-attack-detections/skill/`
and is installed globally in `~/.agents/skills/`):

```bash
python3 /var/home/kim/workspace/suricata-containerized-rootful/agentic-attack-detections/devin/retrohunt.py \
    --eve /var/lib/containers/storage/volumes/suricata-ids-logs/_data/eve.json \
    --eve /var/lib/containers/storage/volumes/suricata-logs/_data/eve.json
# or last N hours from OpenObserve (needs O2_USER/O2_PASS exported):
python3 /var/home/kim/workspace/suricata-containerized-rootful/agentic-attack-detections/devin/retrohunt.py --o2 --hours 24
```

It parses all 94 content rules + generated IP rules and evaluates them
against eve.json/OpenObserve events. Verified against synthetic
events (QwenCode UA → 9727012, `*.oast.fun` → 9727050, IOC IP flow → 9726520)
and the full live corpus: **562k events across both eve.json files
(IPS ~6.5 days + IDS ~24h) → 0 hits**, and **469k events via `--o2 --hours 24`
→ 0 hits** — expected on clean home traffic. First run produced 16 false
positives from a `dst_ip`/`dest_ip` key mismatch (empty dst made every
`$EXTERNAL_NET` rule match) plus a startswith+endswith exact-match bug; both
fixed and re-verified. OpenObserve `_search` caps at 1000 hits and ignores
`from` — the script paginates with `LIMIT/OFFSET` in SQL instead.

**Approximation limits** (it is not Suricata): supports content modifiers,
PCRE, AND conditions, port ranges, `$HOME_NET`/`$EXTERNAL_NET`; `distance`/`within`
approximate; fields we don't log (`http.response_body`, `http.request_body`,
`http.header*`, `tls.sni`, tcp `payload`) can never match. `alert ip` rules are
evaluated on flow events via an IP index. Treat hits as leads to confirm in
OpenObserve or with `hunt-*`/`inspect`.

## Adding content (repo conventions)

- New indicators → append rows to `iocs/indicators.csv` (with `framework`),
  then `build_feeds.py` + `validate.py`, commit regenerated files.
- New framework → follow `docs/adding-a-framework.md`: layout, `FRAMEWORKS`
  entry in `tools/build_feeds.py`, SID range allocation, README tables.
- Rules shared by all frameworks go in `behaviors/`, not a framework folder.
- Sigma/Sentinel IDs are UUIDv5 derived from file path — don't rename files.

## Related skills (this plugin)

`hunt`, `inspect`, `hunt-generic`, `hunt-dns-tunnel`, `hunt-tls-c2`,
`hunt-smb-dcerpc`, `writer`, `explain` — for deeper EVE analysis and rule work.
`suricata-trend-report` (in `~/.agents/skills/`) for the daily OpenObserve
assessment pipeline.
