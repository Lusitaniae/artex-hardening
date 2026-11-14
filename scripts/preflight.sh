#!/usr/bin/env bash
# Pre-flight gate. Nothing starts until every FAIL is cleared.
#
# This is deliberately paranoid and deliberately dumb: it checks the things that
# people skip at 23:00 the night before an engagement — default passwords, an
# exposed bind address, a missing firewall, a clock that will bill you at peak.
#
# Usage:
#   ./scripts/preflight.sh
#   ./scripts/preflight.sh --scope-host 10.0.0.5     (also probes an in-scope host)
set -uo pipefail

ENV_FILE=".env.hardened"
COMPOSE_FILE="docker-compose.hardened.yml"
NETWORK_NAME="artex-hardened_lab"
SCOPE_HOST=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --scope-host) SCOPE_HOST="${2:-}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

PASS=0; WARN=0; FAIL=0
ok()   { printf '\033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
warn() { printf '\033[33mWARN\033[0m %s\n' "$*"; WARN=$((WARN+1)); }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
say()  { printf '\n\033[1m-- %s\033[0m\n' "$*"; }

env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2-; }

say "files"
[ -f "$ENV_FILE" ] && ok "$ENV_FILE present" || bad "$ENV_FILE missing (cp .env.hardened.example .env.hardened)"
[ -f "$COMPOSE_FILE" ] && ok "$COMPOSE_FILE present" || bad "$COMPOSE_FILE missing"
[ -f "$ENV_FILE" ] || { echo; echo "cannot continue without env file"; exit 1; }

PERM="$(stat -c '%a' "$ENV_FILE")"
[ "$PERM" = "600" ] && ok "env file mode 600" || bad "env file mode $PERM — chmod 600 (it holds the admin token)"

say "secrets"
if grep -q 'CHANGE_ME' "$ENV_FILE"; then
  bad "CHANGE_ME placeholders remain: $(grep -o 'CHANGE_ME[A-Z_0-9]*' "$ENV_FILE" | sort -u | tr '\n' ' ')"
else
  ok "no CHANGE_ME placeholders"
fi

PW="$(env_get POSTGRES_PASSWORD)"
if [ "${#PW}" -ge 24 ]; then ok "postgres password length ${#PW}"; else bad "postgres password too short (${#PW} chars, want >=24)"; fi

TOKEN="$(env_get ARTEX_SETUP_TOKEN)"
ADMINPW="$(env_get ARTEX_ADMIN_PASSWORD)"
if [ -n "$TOKEN" ] || [ -n "$ADMINPW" ]; then
  ok "first-run protection set ($([ -n "$TOKEN" ] && echo setup_token || echo admin_password))"
else
  bad "no ARTEX_SETUP_TOKEN or ARTEX_ADMIN_PASSWORD — first visitor to the UI owns the instance"
fi
[ -n "$TOKEN" ] && [ "${#TOKEN}" -lt 32 ] && warn "setup token is ${#TOKEN} chars; 64 hex is better"

APIKEY="$(env_get ARTEX_LLM_API_KEY)"
if [ -n "$APIKEY" ] && [ "${APIKEY:0:4}" != "CHANGE" ]; then ok "LLM API key present"; else bad "ARTEX_LLM_API_KEY not set"; fi

say "exposure"
BIND="$(env_get ARTEX_BIND)"
[ "$BIND" = "127.0.0.1" ] && ok "ARTEX_BIND=127.0.0.1" || bad "ARTEX_BIND=$BIND — must be 127.0.0.1; use an SSH/WireGuard tunnel"

if grep -qE '^\s*-\s*"0\.0\.0\.0:' "$COMPOSE_FILE"; then
  bad "compose publishes on 0.0.0.0"
else
  ok "compose publishes loopback only"
fi
grep -q '8788:' "$COMPOSE_FILE" && bad "port 8788 (traffic recorder) is published — it captures cookies and tokens" \
  || ok "8788 not published"

CORS="$(env_get ARTEX_CORS_ORIGINS)"
[ -z "$CORS" ] && ok "CORS origins empty (same-origin UI)" || warn "CORS widened to: $CORS"

say "images"
IMG="$(env_get ARTEX_IMAGE)"
case "$IMG" in
  *:latest*) bad "ARTEX_IMAGE uses :latest — pin to a commit tag" ;;
  *CHANGE_ME*) bad "ARTEX_IMAGE unset" ;;
  *) ok "ARTEX_IMAGE=$IMG" ;;
esac
grep -q 'pull_policy: never' "$COMPOSE_FILE" && ok "pull_policy: never (no silent updates)" \
  || bad "pull_policy: never missing — the stack can pull new code mid-engagement"
PGI="$(env_get POSTGRES_IMAGE)"
if printf '%s' "$PGI" | grep -qE '@sha256:[0-9a-f]{64}$'; then
  ok "postgres digest-pinned"
else
  bad "POSTGRES_IMAGE not digest-pinned (run scripts/pin-digests.sh)"
fi

say "firewall"
if command -v nft >/dev/null 2>&1 && nft list table inet artex >/dev/null 2>&1; then
  ok "nft table inet artex loaded"
  ELEMS="$(nft list set inet artex lab_net 2>/dev/null | grep -c 'elements' || true)"
  [ "$ELEMS" -gt 0 ] && ok "lab_net populated" || bad "lab_net empty — every packet from the lab is dropped (run egress-apply.sh)"
  if nft list table inet artex | grep -q 'in_scope'; then
    N="$(nft list set inet artex in_scope 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)"
    [ "$N" -gt 0 ] && ok "in_scope has $N target(s)" || bad "in_scope empty — the engagement cannot reach anything"
  fi
  nft list table inet artex | grep -q '169.254.169.254' && ok "metadata endpoint drop present" \
    || bad "169.254.169.254 drop missing"
else
  bad "nft table inet artex not loaded (sudo scripts/egress-apply.sh)"
fi

say "host"
if command -v ss >/dev/null 2>&1; then
  EXPOSED="$(ss -ltnH 2>/dev/null | awk '$4 ~ /^(0\.0\.0\.0|\*|\[::\]):(8787|8788|5432)$/ {print $4}' | paste -sd' ' -)"
  [ -z "$EXPOSED" ] && ok "8787/8788/5432 not listening on wildcard" || bad "exposed listeners: $EXPOSED"
else
  warn "ss not available; check listeners manually"
fi

if command -v timedatectl >/dev/null 2>&1; then
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes; then
    ok "clock NTP-synchronised (off-peak billing depends on this)"
  else
    warn "clock not NTP-synced — you may be billed at peak while believing you are off-peak"
  fi
fi

FREE_G="$(df -BG --output=avail . 2>/dev/null | tail -1 | tr -dc '0-9')"
[ -n "$FREE_G" ] && { [ "$FREE_G" -ge 20 ] && ok "disk free ${FREE_G}G" || bad "disk free ${FREE_G}G — tool output and pcaps fill disks fast"; }

say "compose validation"
if docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config -q 2>/tmp/pf_compose.err; then
  ok "compose config valid"
else
  bad "compose config invalid: $(head -3 /tmp/pf_compose.err | tr '\n' ' ')"
fi

say "egress behaviour (inside the lab network)"
if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  if [ -n "${IMG}" ] && docker image inspect "$IMG" >/dev/null 2>&1; then
    for target in "http://198.51.100.7/" "http://169.254.169.254/"; do
      OUT="$(docker run --rm --network "$NETWORK_NAME" --entrypoint sh "$IMG" \
        -c "curl -sS --max-time 5 -o /dev/null '$target' 2>&1 || echo BLOCKED" 2>/dev/null | tail -1)"
      case "$OUT" in
        *BLOCKED*) ok "blocked: $target" ;;
        "")        warn "no curl in image; cannot probe $target" ;;
        *)         bad "REACHABLE: $target -> $OUT" ;;
      esac
    done
  else
    warn "image $IMG not built yet — skipping live egress probes"
  fi
else
  warn "network $NETWORK_NAME does not exist yet (stack not started)"
fi

if [ -n "$SCOPE_HOST" ] && docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  say "in-scope reachability"
  if docker run --rm --network "$NETWORK_NAME" --entrypoint sh "$IMG" \
      -c "nc -z -w3 '$SCOPE_HOST' 443 && echo OPEN" 2>/dev/null | grep -q OPEN; then
    ok "$SCOPE_HOST:443 reachable (expected)"
  else
    warn "$SCOPE_HOST:443 not reachable — check scope.allow or that the host is up"
  fi
fi

say "summary"
printf '  pass %d   warn %d   fail %d\n' "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo
  echo "Do not start the stack. Clear every FAIL above."
  exit 1
fi
echo
echo "Clear. Start with:"
echo "  docker compose --env-file $ENV_FILE -f $COMPOSE_FILE up -d"
