#!/usr/bin/env python3
"""Retro-hunt ThreatDefence agentic-attack-detections Suricata rules against our own data.

Evaluates the repo's .rules files (behaviors + frameworks/*/suricata) against
Suricata EVE JSON, either a local eve.json export or live OpenObserve streams.

This is an approximation of Suricata semantics, not a substitute for the engine:
  - supports content/startswith/endswith/nocase/offset/depth, pcre, AND-ed
    conditions, direction (to_server/to_client via field groups), dest port
    ranges, $HOME_NET/$EXTERNAL_NET/$HTTP_SERVERS approximations
  - distance/within are approximated as ordered-window matches
  - fields we don't log (http.response_body, http.request_body, http.header,
    tls.sni on our sensors, tcp payload) simply never match
  - alert ip rules reduce to reported-IP membership checks on src/dst

Usage:
    python3 retrohunt.py --eve /path/to/eve.json [--eve ...]
    python3 retrohunt.py --o2 --hours 24          # needs O2_USER/O2_PASS env
"""
import argparse
import base64
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

# agentic-attack-detections rules repo = parent of this script's devin/ dir
REPO = Path(__file__).resolve().parents[1]
RULE_FILES = sorted(REPO.glob("behaviors/suricata/*.rules")) + sorted(
    REPO.glob("frameworks/*/suricata/*.rules")
)

PRIVATE = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
)]


def is_home(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in PRIVATE)


def is_ext(ip):
    return not is_home(ip)


# ---------------------------------------------------------------- rule parsing

class Cond:
    """One content/pcre condition on a sticky buffer."""
    def __init__(self, field, value, flags, pcre=False):
        self.field = field
        self.value = value
        self.flags = flags
        self.pcre = pcre

    def test(self, buf):
        if buf is None:
            return False
        if self.pcre:
            return re.search(self.value, buf, re.I if "i" in self.flags else 0) is not None
        v = self.value
        flags = self.flags
        if "startswith" in flags and "endswith" in flags:
            n = len(v)
            if "nocase" in flags:
                return len(buf) == n and buf.lower() == v.lower()
            return buf == v
        if "startswith" in flags:
            return buf.startswith(v) if "nocase" not in flags else buf[:len(v)].lower() == v.lower()
        if "endswith" in flags:
            return buf.endswith(v) if "nocase" not in flags else buf[-len(v):].lower() == v.lower()
        if "nocase" in flags:
            return v.lower() in buf.lower()
        return v in buf


class Rule:
    def __init__(self, raw, source):
        self.raw = raw
        self.source = source
        m = re.match(r"alert\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$", raw.strip())
        if not m:
            raise ValueError(f"unparseable rule: {raw[:80]}")
        self.proto, self.saddr, self.sport, self.daddr, self.dport = m.groups()[:5]
        body = m.group(6)
        self.msg = re.search(r'msg:"([^"]*)"', body)
        self.msg = self.msg.group(1) if self.msg else ""
        sid = re.search(r"\bsid:(\d+)", body)
        self.sid = sid.group(1) if sid else "?"
        meta = re.search(r"metadata:([^)]*)", body)
        self.confidence = ""
        if meta:
            cm = re.search(r"confidence (\w+)", meta.group(1))
            self.confidence = cm.group(1) if cm else ""
        self.conds = []
        self._parse_conditions(body)

    def _parse_conditions(self, body):
        # strip msg/classtype/sid/rev/metadata/threshold/flow options we handle separately
        body = re.sub(r'\b(msg|classtype|sid|rev|metadata|threshold|flow|appid|tls\.version|stream|file\.data|file\.name|file\.magic|file\.size|file\.state|file\.ext|fileext|filename|reference|priority)\b:[^;]*;', "", body)
        # sequential scan: STICKY; content:"..." mods; pcre:"/.../flags";
        self.conds = []
        cur_field = None
        for tm in re.finditer(r'(\w+(?:\.\w+)*)\s*;|content:"((?:[^"\\]|\\.)*)"\s*((?:;|\s|\b(?:startswith|endswith|nocase|offset|depth|distance|within|dotprefix|fast_pattern|isdata|rawbytes|http_uri|http_header|http_cookie|http_raw_header|http_user_agent|http_method|http_host|http_client_body|http_server_body)\b)*)|pcre:"((?:[^"\\]|\\.)*)"', body):
            if tm.group(1):  # sticky buffer
                f = tm.group(1)
                if f in ("http", "dns", "tls", "tcp", "ip", "file"):
                    continue
                cur_field = f
                continue
            val = tm.group(2) if tm.group(2) is not None else tm.group(4)
            mods = tm.group(3) or ""
            pcre = tm.group(4) is not None
            if val is None:
                continue
            if pcre:
                mm = re.match(r"/(.*)/([a-zA-Z]*)$", val, re.S)
                if not mm:
                    continue
                pattern, flags = mm.group(1), mm.group(2)
                self.conds.append(Cond(cur_field or "payload", pattern, flags, pcre=True))
                continue
            # unescape \" and decode |hex| runs like |0d 0a|
            v = val.replace('\\"', '"')
            def hexsub(m):
                return bytes(int(x, 16) for x in m.group(1).split()).decode("latin1")
            v = re.sub(r"\|([0-9a-fA-F ]+)\|", hexsub, v)
            flags = []
            for fl in ("startswith", "endswith", "nocase", "offset", "depth", "distance", "within", "dotprefix"):
                if re.search(rf"\b{fl}\b", mods):
                    flags.append(fl)
            self.conds.append(Cond(cur_field or "payload", v, flags))

    # ------------------------------------------------------------ evaluation

    def addr_ok(self, ev):
        src, dst = ev.get("src_ip", ""), ev.get("dest_ip", "")
        def side(addr_spec, ip):
            if addr_spec == "any":
                return True
            if addr_spec == "$HOME_NET":
                return is_home(ip)
            if addr_spec == "$EXTERNAL_NET":
                return is_ext(ip)
            if addr_spec == "$HTTP_SERVERS":
                return True  # approximated: http events are already web traffic
            if addr_spec == "$SMTP_SERVERS":
                return False
            return addr_spec == ip
        if not side(self.saddr, src) or not side(self.daddr, dst):
            return False
        def port_ok(spec, port):
            if spec == "any":
                return True
            if ":" in spec:
                try:
                    lo, hi = spec.split(":")
                    return int(lo) <= port <= int(hi)
                except ValueError:
                    return False
            return spec == str(port)
        try:
            dport = int(ev.get("dest_port") or 0)
        except (TypeError, ValueError):
            dport = 0
        if not port_ok(self.dport, dport):
            return False
        return True

    FIELD_MAP = {
        "http.user_agent": ["http_user_agent"],
        "http.uri": ["http_uri"],
        "http.host": ["http_host"],
        "http.method": ["http_method"],
        "http.request_body": ["http_request_body"],
        "http.response_body": ["http_response_body"],
        "http.header": ["http_header"],
        "http.header_names": ["http_header_names"],
        "http.server": ["http_server"],
        "dns.query": ["dns_queries"],
        "tls.sni": ["tls_sni"],
        "tls.cert_subject": ["tls_cert_subject"],
        "tls.cert_issuer": ["tls_cert_issuer"],
        "payload": ["payload"],
    }

    def eval_event(self, ev):
        if not self.addr_ok(ev):
            return False
        # group conds by sticky field
        groups = {}
        for c in self.conds:
            groups.setdefault(c.field, []).append(c)
        for field, conds in groups.items():
            keys = self.FIELD_MAP.get(field)
            if keys is None:
                return False  # unknown buffer -> can't match
            bufs = []
            for k in keys:
                v = ev.get(k)
                if v is None:
                    continue
                if isinstance(v, list):
                    bufs.extend(str(x) for x in v)
                else:
                    bufs.append(str(v))
            if not bufs:
                return False
            if not self._match_group(bufs, conds):
                return False
        return True

    def _match_group(self, bufs, conds):
        # every cond must match (on possibly different buffers, except ordered
        # distance/within pairs which must share a buffer)
        used_ordered = any("distance" in c.flags or "within" in c.flags for c in conds)
        for c in conds:
            if used_ordered and ("distance" in c.flags or "within" in c.flags):
                continue  # handled in ordered pass below
            if not any(c.test(b) for b in bufs):
                return False
        if used_ordered:
            # ordered pass: all conds must match in sequence within one buffer
            ok = False
            for buf in bufs:
                pos = 0
                good = True
                for c in conds:
                    if c.pcre:
                        m = re.search(c.value, buf[pos:], re.I if "i" in c.flags else 0)
                        if not m:
                            good = False
                            break
                        pos += m.end()
                        continue
                    idx = buf.find(c.value, pos) if "nocase" not in c.flags else buf.lower().find(c.value.lower(), pos)
                    if idx < 0:
                        good = False
                        break
                    pos = idx + len(c.value)
                if good:
                    ok = True
                    break
            if not ok:
                return False
        return True


IP_LITERAL = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^[0-9a-fA-F:]+$")


class IpRule:
    """Fast path for `alert ip` rules: literal-IP side indexed for O(1) lookup."""
    __slots__ = ("sid", "msg", "confidence", "source", "src_ips", "dst_ips",
                 "src_spec", "dst_spec")

    def __init__(self, rule):
        self.sid, self.msg = rule.sid, rule.msg
        self.confidence, self.source = rule.confidence, rule.source
        self.src_spec, self.dst_spec = rule.saddr, rule.daddr
        self.src_ips = self._ips(rule.saddr)
        self.dst_ips = self._ips(rule.daddr)

    @staticmethod
    def _ips(spec):
        m = re.search(r"\[([^\]]+)\]", spec)
        if not m:
            return frozenset()
        return frozenset(x.strip() for x in m.group(1).split(","))

    def index_key_out(self):
        # $HOME_NET/any -> [ips]: interesting side is dst
        return self.dst_ips

    def index_key_in(self):
        # [ips] -> $HOME_NET/any: interesting side is src
        return self.src_ips

    def matches(self, ev):
        src, dst = ev.get("src_ip", ""), ev.get("dest_ip", "")

        def side(spec, ips, ip):
            if spec == "any":
                return True
            if spec == "$HOME_NET":
                return is_home(ip)
            if spec == "$EXTERNAL_NET":
                return is_ext(ip)
            if spec.startswith("["):
                return ip in ips
            return spec == ip
        return side(self.src_spec, self.src_ips, src) and side(self.dst_spec, self.dst_ips, dst)


def load_rules():
    content_rules = []   # keyed later by proto
    ip_out = {}          # dst_ip -> [IpRule]  ($HOME_NET -> [ips])
    ip_in = {}           # src_ip -> [IpRule]  ([ips] -> $HOME_NET)
    ip_other = []
    for p in RULE_FILES:
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line.startswith("alert "):
                continue
            r = Rule(line, p.name)
            if r.proto == "ip":
                ir = IpRule(r)
                # classify by which side carries literal IPs
                if ir.dst_ips and not ir.src_ips:
                    for ip in ir.dst_ips:
                        ip_out.setdefault(ip, []).append(ir)
                elif ir.src_ips and not ir.dst_ips:
                    for ip in ir.src_ips:
                        ip_in.setdefault(ip, []).append(ir)
                else:
                    ip_other.append(ir)
            else:
                content_rules.append(r)
    return content_rules, ip_out, ip_in, ip_other


# ------------------------------------------------------------------ events

def eve_events(path):
    with open(path) as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            et = e.get("event_type")
            ev = {
                "ts": e.get("timestamp", ""),
                "src_ip": e.get("src_ip", ""),
                "dest_ip": e.get("dest_ip", ""),
                "dest_port": e.get("dest_port"),
                "src_port": e.get("src_port"),
                "event_type": et,
            }
            if et == "http":
                h = e.get("http", {})
                ev["http_host"] = h.get("hostname")
                ev["http_uri"] = h.get("url")
                ev["http_user_agent"] = h.get("http_user_agent")
            elif et == "dns":
                d = e.get("dns", {})
                names = []
                if d.get("rrname"):
                    names.append(d["rrname"])
                for a in d.get("answers", []) or []:
                    if a.get("rrname"):
                        names.append(a["rrname"])
                ev["dns_queries"] = names
            elif et == "tls":
                t = e.get("tls", {})
                ev["tls_sni"] = t.get("sni")
                ev["tls_cert_subject"] = t.get("subject")
                ev["tls_cert_issuer"] = t.get("issuerdn")
            elif et == "alert":
                ev["alert_signature"] = e.get("alert", {}).get("signature", "")
            yield ev


def o2_events(hours, streams=("suricata_ips", "suricata_ids")):
    base = os.environ.get("O2_HOST", "http://localhost:5080").rstrip("/")
    org = os.environ.get("O2_ORG", "default")
    user, pw = os.environ.get("O2_USER"), os.environ.get("O2_PASS")
    if not user or not pw:
        sys.exit("O2_USER/O2_PASS required for --o2")
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    end = int(time.time() * 1e6)
    start = end - int(hours * 3600 * 1e6)
    for stream in streams:
        # pull the fields rules can match on, for the event types that carry them
        sql = (
            f'SELECT _timestamp, event_type, src_ip, dest_ip, dest_port, src_port, '
            f'http_hostname, http_url, http_http_user_agent, dns_queries, dns_type, '
            f'tls_sni, tls_subject, tls_issuerdn, sensor '
            f'FROM "{stream}" WHERE event_type IN (\'http\',\'dns\',\'tls\',\'flow\',\'alert\')'
        )
        # OpenObserve caps _search at 1000 hits and ignores `from`; paginate
        # with LIMIT/OFFSET in the SQL (ORDER BY keeps pages stable).
        base_sql = sql
        offset, total = 0, 0
        while True:
            sql = f"{base_sql} ORDER BY _timestamp LIMIT 1000 OFFSET {offset}"
            payload = {"query": {"sql": sql, "start_time": start, "end_time": end},
                       "size": 1000}
            req = urllib.request.Request(
                f"{base}/api/{org}/_search?type=logs",
                data=json.dumps(payload).encode(), method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", "Basic " + auth)
            with urllib.request.urlopen(req, timeout=300) as r:
                hits = json.loads(r.read()).get("hits", [])
            total += len(hits)
            for h in hits:
                et = h.get("event_type")
                ev = {
                    "ts": h.get("date"),
                    "src_ip": h.get("src_ip", ""),
                    "dest_ip": h.get("dest_ip", ""),
                    "dest_port": h.get("dest_port"),
                    "src_port": h.get("src_port"),
                    "event_type": et,
                    "sensor": h.get("sensor"),
                }
                if et == "http":
                    ev["http_host"] = h.get("http_hostname")
                    ev["http_uri"] = h.get("http_url")
                    ev["http_user_agent"] = h.get("http_http_user_agent")
                elif et == "dns":
                    names = []
                    raw = h.get("dns_queries")
                    if raw:
                        try:
                            for q in json.loads(raw):
                                if q.get("rrname"):
                                    names.append(q["rrname"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    ev["dns_queries"] = names
                    ev["dns_type"] = h.get("dns_type")
                elif et == "tls":
                    ev["tls_sni"] = h.get("tls_sni")
                    ev["tls_cert_subject"] = h.get("tls_subject")
                    ev["tls_cert_issuer"] = h.get("tls_issuerdn")
                elif et == "alert":
                    ev["alert_signature"] = h.get("alert_signature") or h.get("signature")
                yield ev
            if len(hits) < 1000:
                break
            offset += 1000
        print(f"# {stream}: {total} events", file=sys.stderr)


# --------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eve", action="append", default=[], help="eve.json path (repeatable)")
    ap.add_argument("--o2", action="store_true", help="pull from OpenObserve")
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--rules", default=str(REPO), help="repo root containing behaviors/ and frameworks/")
    ap.add_argument("--json", dest="json_out", default=None,
                    help="also write hits as JSON lines to this path")
    args = ap.parse_args()

    global RULE_FILES
    repo = Path(args.rules)
    RULE_FILES = sorted(repo.glob("behaviors/suricata/*.rules")) + sorted(
        repo.glob("frameworks/*/suricata/*.rules")
    )
    content_rules, ip_out, ip_in, ip_other = load_rules()
    by_proto = {}
    for r in content_rules:
        by_proto.setdefault(r.proto, []).append(r)
    print(f"loaded {len(content_rules)} content rules + "
          f"{sum(len(v) for v in ip_out.values()) + sum(len(v) for v in ip_in.values()) + len(ip_other)} ip rules "
          f"from {len(RULE_FILES)} files", file=sys.stderr)

    def event_stream():
        if args.eve:
            for p in args.eve:
                for ev in eve_events(p):
                    ev["_src"] = Path(p).name
                    yield ev
        if args.o2:
            for ev in o2_events(args.hours):
                ev["_src"] = "openobserve"
                yield ev

    hits = []
    seen = set()
    n_ev = 0
    by_src, by_type = {}, {}
    ts_min = ts_max = ""
    # --hours also bounds --eve scans: exports are append-ordered multi-day
    # files, so filtering by event ts keeps daily runs to the recent window.
    cutoff = ""
    if args.hours and args.eve and not args.o2:
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=args.hours)).strftime(
            "%Y-%m-%dT%H:%M:%S")
    for ev in event_stream():
        ts0 = ev.get("ts") or ""
        if cutoff and ts0 and ts0[:19] < cutoff:
            continue
        n_ev += 1
        by_src[ev.get("_src", "?")] = by_src.get(ev.get("_src", "?"), 0) + 1
        et = ev["event_type"]
        by_type[et] = by_type.get(et, 0) + 1
        ts = ev.get("ts") or ""
        if ts:
            ts_min = ts if not ts_min or ts < ts_min else ts_min
            ts_max = ts if ts > ts_max else ts_max
        # --- ip rules on flow events (O(1) index lookups) ---
        if et == "flow":
            cands = ip_out.get(ev.get("dest_ip"), []) + ip_in.get(ev.get("src_ip"), []) + ip_other
            for ir in cands:
                if ir.matches(ev):
                    key = (ir.sid, ev.get("src_ip"), ev.get("dest_ip"), ev.get("dest_port"))
                    if key not in seen:
                        seen.add(key)
                        hits.append((ir, ev))
            proto_rules = by_proto.get("tcp", ())
        else:
            proto_rules = by_proto.get(et, ())
        for r in proto_rules:
            if r.eval_event(ev):
                key = (r.sid, ev.get("src_ip"), ev.get("dest_ip"), ev.get("dest_port"),
                       str(ev.get("dns_queries") or ev.get("http_uri") or ev.get("http_host") or "")[:80])
                if key not in seen:
                    seen.add(key)
                    hits.append((r, ev))
        if n_ev % 50000 == 0:
            print(f"  ... {n_ev} events, {len(hits)} hits", file=sys.stderr)

    print(f"\n{'=' * 60}")
    print(f"SCAN SUMMARY — {n_ev} events")
    for src, cnt in sorted(by_src.items()):
        print(f"  source: {src}: {cnt} events")
    if ts_min:
        print(f"  window: {ts_min} .. {ts_max}")
    top = sorted(by_type.items(), key=lambda kv: -kv[1])
    print("  event types: " + ", ".join(f"{t}={c}" for t, c in top))
    print(f"  rules: {len(content_rules)} content + "
          f"{sum(len(v) for v in ip_out.values()) + sum(len(v) for v in ip_in.values()) + len(ip_other)} ip")
    print(f"{'=' * 60}\n")
    print(f"{len(hits)} unique hits\n")
    json_f = open(args.json_out, "w") if args.json_out else None
    for r, ev in hits:
        et = ev.get("event_type")
        if et == "dns":
            detail = "q=" + ",".join(ev.get("dns_queries") or [])
        elif et == "http":
            detail = f"{ev.get('http_host') or ''}{ev.get('http_uri') or ''} UA={ev.get('http_user_agent') or ''}"
        elif et == "tls":
            detail = f"subj={ev.get('tls_cert_subject') or ''}"
        elif et == "flow":
            detail = f"proto flow {ev.get('src_ip')}->{ev.get('dest_ip')}"
        else:
            detail = ""
        if json_f:
            json_f.write(json.dumps({
                "sid": r.sid, "signature": r.msg,
                "confidence": r.confidence, "source": r.source,
                "src_ip": ev.get("src_ip"), "src_port": ev.get("src_port"),
                "dest_ip": ev.get("dest_ip"), "dest_port": ev.get("dest_port"),
                "event_type": et, "ts": ev.get("ts") or ev.get("timestamp"),
                "detail": detail[:300], "eve_src": ev.get("_src"),
            }) + "\n")
        print(f"[{r.sid}] {r.msg}  (conf {r.confidence or '?'}, {r.source})")
        print(f"    {ev.get('src_ip')}:{ev.get('src_port')} -> {ev.get('dest_ip')}:{ev.get('dest_port')} {et} {ev.get('ts','')} {detail[:160]}")
    if json_f:
        json_f.close()


if __name__ == "__main__":
    main()
