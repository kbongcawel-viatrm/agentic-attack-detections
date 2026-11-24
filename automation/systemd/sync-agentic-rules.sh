#!/usr/bin/env bash
# sync-agentic-rules.sh — daily sync of ThreatDefence agentic-attack-detections
# Suricata rules AND the rule-files list in suricata.yaml.
#
# 1. Fetches latest upstream main in the agentic-attack-detections submodule.
# 2. Copies every *.rules under frameworks/*/suricata/, behaviors/suricata/ and
#    behaviors/*/suricata/ into the repo mirror (suricata_rules/) and the live
#    rules dir (/var/lib/suricata-ids/rules) shared by suricata.service (IPS)
#    and suricata-ids.service (IDS).
# 3. Adds newly-appeared agentic rule files to `rule-files:` in both
#    suricata_yaml/suricata.yaml and the live config, and prunes entries for
#    rules upstream removed. *-ip.rules are deployed but never added to
#    rule-files (matches existing convention).
# 4. Runs `suricata -T` ONCE against the live config + rules after changes are
#    applied; on failure the previous live rules/config are restored.
# 5. Restarts both quadlet services — only when something actually changed.
#
# Designed to run as root from agentic-rules-update.timer. Repo/mirror writes
# are done as the repo owner so .git and suricata_rules/ stay user-owned.
#
# Env overrides (testing): AGENTIC_REPO, AGENTIC_MIRROR, AGENTIC_LIVE,
# AGENTIC_CONFIG, AGENTIC_WORK_YAML, AGENTIC_IMAGE, AGENTIC_SKIP_PULL=1,
# AGENTIC_SKIP_VALIDATE=1, AGENTIC_SKIP_SYSTEMCTL=1.
set -euo pipefail

REPO="${AGENTIC_REPO:-/var/home/kim/workspace/suricata-containerized-rootful/agentic-attack-detections}"
MIRROR="${AGENTIC_MIRROR:-/var/home/kim/workspace/suricata-containerized-rootful/suricata_rules}"
LIVE="${AGENTIC_LIVE:-/var/lib/suricata-ids/rules}"
CONFIG="${AGENTIC_CONFIG:-/var/lib/suricata-ids/config}"
WORK_YAML="${AGENTIC_WORK_YAML:-/var/home/kim/workspace/suricata-containerized-rootful/suricata_yaml/suricata.yaml}"
LIVE_YAML="$CONFIG/suricata.yaml"
IMAGE="${AGENTIC_IMAGE:-docker.io/jasonish/suricata}"
REPO_OWNER="${AGENTIC_REPO_OWNER:-kim}"
MANIFEST=.agentic-rules.manifest

log()  { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
die()  { log "ERROR: $*" >&2; exit 1; }

# Run a command as the repo owner when we are root, else directly.
as_owner() {
    if [[ $EUID -eq 0 ]]; then
        # HOME must point at the owner's home or ssh/git won't find ~/.ssh/config
        runuser -u "$REPO_OWNER" -- env \
            HOME="$(getent passwd "$REPO_OWNER" | cut -d: -f6)" \
            USER="$REPO_OWNER" "$@"
    else
        "$@"
    fi
}

[[ -e "$REPO/.git" ]] || die "submodule not found at $REPO"
[[ -d "$MIRROR" ]] || die "mirror dir missing: $MIRROR"
mkdir -p "$LIVE"

# --- 1. Fetch upstream -------------------------------------------------------
OLD_REV=$(as_owner git -C "$REPO" rev-parse HEAD)
if [[ "${AGENTIC_SKIP_PULL:-0}" != 1 ]]; then
    as_owner git -C "$REPO" fetch --quiet origin main
    as_owner git -C "$REPO" reset --hard --quiet origin/main
fi
NEW_REV=$(as_owner git -C "$REPO" rev-parse HEAD)
log "upstream: ${OLD_REV:0:8} -> ${NEW_REV:0:8}"

# --- 2. Stage upstream rules --------------------------------------------------
STAGE=$(mktemp -d)
chmod 0755 "$STAGE"   # staged files are installed by the repo owner (kim)
trap 'rm -rf "$STAGE" "$BAK"; rm -f "$WANT" "$OLD_NONIP" "$REMOVE" 2>/dev/null || true' EXIT
BAK= WANT= OLD_NONIP= REMOVE=

shopt -s nullglob
count=0
for dir in "$REPO"/frameworks/*/suricata "$REPO"/behaviors/suricata "$REPO"/behaviors/*/suricata; do
    for f in "$dir"/*.rules; do
        install -m 0644 "$f" "$STAGE/$(basename "$f")"
        count=$((count + 1))
    done
done
shopt -u nullglob
((count)) || die "no *.rules found under $REPO/{frameworks,behaviors}/**/suricata"
log "staged $count rule files"

# Names that belong in rule-files: everything except generated *-ip.rules lists.
WANT=$(mktemp)
for f in "$STAGE"/*.rules; do
    b=$(basename "$f")
    [[ $b == *-ip.rules ]] || echo "$b"
done | sort > "$WANT"

# Previously managed non-ip names (for pruning rule-files entries upstream dropped).
OLD_NONIP=$(mktemp)
if [[ -f "$LIVE/$MANIFEST" ]]; then
    grep -v -- '-ip\.rules$' "$LIVE/$MANIFEST" | sort > "$OLD_NONIP" || true
fi
REMOVE=$(mktemp)
comm -23 "$OLD_NONIP" "$WANT" > "$REMOVE"

# --- 3. Detect changes --------------------------------------------------------
rules_changed=0
for f in "$STAGE"/*.rules; do
    name=$(basename "$f")
    cmp -s "$f" "$LIVE/$name" || { rules_changed=1; log "rule changed: $name"; }
done
removed_rules=()
if [[ -f "$LIVE/$MANIFEST" ]]; then
    while IFS= read -r name; do
        [[ -f "$STAGE/$name" ]] && continue
        [[ -f "$LIVE/$name" ]] && removed_rules+=("$name")
    done < "$LIVE/$MANIFEST"
fi
if ((${#removed_rules[@]})); then
    rules_changed=1
    log "rules removed upstream: ${removed_rules[*]}"
fi

# --- 4. Sync rule-files in both suricata.yaml copies --------------------------
# Adds WANT entries missing from the rule-files block, drops REMOVE entries.
sync_rule_files() { # $1 = yaml path; prints path of updated file or nothing
    local yaml=$1 out
    out=$(mktemp)
    awk -v wantf="$WANT" -v rmf="$REMOVE" '
    BEGIN {
        while ((getline l < wantf) > 0) want[l]=1
        while ((getline l < rmf)  > 0) rm[l]=1
        nw = asorti(want, wadd)   # sorted rule-file names to ensure present
    }
    /^rule-files:/ { inblock=1; print; next }
    inblock==1 && $0 ~ /^  - / {
        name=$2
        if (name in rm) next
        seen[name]=1
        print; next
    }
    inblock==1 && ($0 ~ /^[[:space:]]*$/ || $0 ~ /^[^[:space:]]/) {
        for (i=1; i<=nw; i++) if (!(wadd[i] in seen) && !(wadd[i] in rm)) print "  - " wadd[i]
        inblock=0
        print; next
    }
    inblock==1 { print; next }   # comments/blank-ish lines inside the block
    { print }
    END { if (inblock==1) for (i=1; i<=nw; i++) if (!(wadd[i] in seen) && !(wadd[i] in rm)) print "  - " wadd[i] }
    ' "$yaml" > "$out"
    if cmp -s "$yaml" "$out"; then
        rm -f "$out"
    else
        echo "$out"
    fi
}

yaml_changed=0
for target in "work:$WORK_YAML" "live:$LIVE_YAML"; do
    kind=${target%%:*}; path=${target#*:}
    [[ -f $path ]] || { log "WARN: $path missing; skipping rule-files sync"; continue; }
    newfile=$(sync_rule_files "$path") || true
    [[ -z $newfile ]] && continue
    # install preserving mode/owner conventions
    if [[ $kind == work ]]; then
        as_owner install -m "$(stat -c %a "$path")" "$newfile" "$path"
    else
        install -m "$(stat -c %a "$path")" "$newfile" "$path"
    fi
    rm -f "$newfile"
    yaml_changed=1
    log "rule-files updated in $path"
done

if [[ $rules_changed -eq 0 && $yaml_changed -eq 0 ]]; then
    log "no changes; nothing to do"
    exit 0
fi

# --- 5. Backup live state for rollback ---------------------------------------
BAK=$(mktemp -d)
chmod 0700 "$BAK"
cp -a "$LIVE_YAML" "$BAK/suricata.yaml" 2>/dev/null || true
if [[ -f "$LIVE/$MANIFEST" ]]; then
    while IFS= read -r name; do
        [[ -f "$LIVE/$name" ]] && install -m 0644 "$LIVE/$name" "$BAK/$name"
    done < "$LIVE/$MANIFEST"
fi
cp "$LIVE/$MANIFEST" "$BAK/$MANIFEST" 2>/dev/null || true

restore_live() {
    log "restoring previous live rules/config"
    # remove currently-managed files, then put backups back
    if [[ -f "$LIVE/$MANIFEST" ]]; then
        while IFS= read -r name; do rm -f "$LIVE/$name"; done < "$LIVE/$MANIFEST"
    fi
    for f in "$BAK"/*.rules; do
        [[ -e $f ]] && install -m 0644 "$f" "$LIVE/$(basename "$f")"
    done
    [[ -f "$BAK/$MANIFEST" ]] && install -m 0644 "$BAK/$MANIFEST" "$LIVE/$MANIFEST"
    [[ -f "$BAK/suricata.yaml" ]] && install -m "$(stat -c %a "$LIVE_YAML")" "$BAK/suricata.yaml" "$LIVE_YAML"
}

# --- 6. Apply rules to mirror + live ------------------------------------------
apply_dir() { # $1=target dir, $2="owner"|"root"
    local target=$1 mode=$2 name f
    for f in "$STAGE"/*.rules; do
        name=$(basename "$f")
        if [[ $mode == owner ]]; then
            as_owner install -m 0770 "$f" "$target/$name"
        else
            install -m 0644 "$f" "$target/$name"
        fi
    done
    if [[ -f "$target/$MANIFEST" ]]; then
        while IFS= read -r name; do
            [[ -f "$STAGE/$name" ]] && continue
            rm -f "$target/$name"
        done < "$target/$MANIFEST"
    fi
    for f in "$STAGE"/*.rules; do basename "$f"; done > "$STAGE/$MANIFEST"
    if [[ $mode == owner ]]; then
        as_owner install -m 0660 "$STAGE/$MANIFEST" "$target/$MANIFEST"
    else
        install -m 0644 "$STAGE/$MANIFEST" "$target/$MANIFEST"
    fi
}

log "applying to mirror $MIRROR"
apply_dir "$MIRROR" owner
log "applying to live $LIVE"
apply_dir "$LIVE" root

# --- 7. Single validation pass against live config + rules --------------------
if [[ "${AGENTIC_SKIP_VALIDATE:-0}" == 1 ]]; then
    log "AGENTIC_SKIP_VALIDATE=1; skipping suricata -T validation"
elif command -v podman >/dev/null 2>&1; then
    log "validating live ruleset with suricata -T"
    if ! podman run --rm --name suricata-agentic-rule-test --network host \
        -v "$CONFIG":/etc/suricata/custom:ro,Z \
        -v "$LIVE":/etc/suricata/rules:ro,Z \
        --entrypoint /bin/sh \
        "$IMAGE" -c 'suricata -T -c /etc/suricata/custom/suricata.yaml -l /tmp' \
        > /tmp/agentic-suricata-test.log 2>&1; then
        tail -20 /tmp/agentic-suricata-test.log >&2 || true
        restore_live
        die "suricata -T failed; live rules/config restored, services NOT restarted"
    fi
    tail -5 /tmp/agentic-suricata-test.log | grep -E 'rules successfully|ERROR' || true
else
    log "WARN: podman not found; skipping suricata -T validation"
fi

# --- 8. Restart on change ------------------------------------------------------
if [[ "${AGENTIC_SKIP_SYSTEMCTL:-0}" == 1 ]]; then
    log "AGENTIC_SKIP_SYSTEMCTL=1; skipping service restart"
    exit 0
fi
log "restarting suricata.service and suricata-ids.service"
systemctl try-restart suricata.service suricata-ids.service
for s in suricata.service suricata-ids.service; do
    systemctl is-active --quiet "$s" && log "$s active" || log "WARN: $s not active"
done
log "done"
