#!/usr/bin/env bash
# Populate the nftables sets and apply the containment ruleset.
#
# Default mode ("proxy"): containers may reach exactly one thing off-box — the
# domain-allowlisted squid relay on the bridge gateway. Provider IP rotation stops
# mattering, and every model call is logged by domain.
#
# Direct mode (--direct): containers may reach pinned provider IPs on 443. Fragile;
# CDN-fronted endpoints rotate and your run dies with a lookalike "outage".
#
# Usage:
#   sudo ./scripts/egress-apply.sh
#   sudo ./scripts/egress-apply.sh --direct
#   sudo ./scripts/egress-apply.sh --dry-run
#   sudo ./scripts/egress-apply.sh --profile acme-2026-11
#   sudo ./scripts/egress-apply.sh --open          # no client scope, full public egress
#   ./scripts/egress-apply.sh --list-profiles
#
# A profile is one engagement's allowlists under nftables/profiles/<name>/.
# Generality lives in the profile mechanism, not in a wider allowlist: you can
# take any assignment, but each one is a separate closed set that is applied
# for its window and replaced by the next --profile apply. There is deliberately
# no "everything" profile.
set -euo pipefail

MODE="proxy"
DRY=0
REVERT=0
PROFILE=""
OPEN=0
SUBNET="${SUBNET:-172.28.0.0/24}"
GATEWAY="${GATEWAY:-172.28.0.1}"
# The ruleset is written for the hardened compose bridge. A deployment that
# uses the project's own compose gets a different subnet and gateway (Docker
# picks 172.18.0.0/16 by default), and the two literal gateway rules below
# would then be wrong -- silently, and in the direction of "UI works, agent
# uncontained". So render the file with the real gateway instead of trusting it.
DEFAULT_GATEWAY="172.28.0.1"
NFT_FILE="nftables/artex-egress.nft"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --direct) MODE="direct"; shift ;;
    --proxy)  MODE="proxy"; shift ;;
    --dry-run) DRY=1; shift ;;
    --revert) REVERT=1; shift ;;
    --open) OPEN=1; shift ;;
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    --list-profiles)
      [ -d nftables/profiles ] || { echo "no nftables/profiles directory"; exit 0; }
      for p in nftables/profiles/*/; do [ -d "$p" ] && basename "$p"; done
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# The relay is a SECOND gate, not just the LLM path: the app's `global_proxy`
# setting sends target traffic through it too. Open mode must therefore make the
# relay transparent as well, or the kernel is open and every non-allowlisted
# domain still gets 403. One marked line, greppable and reversible.
SQUID_CONF="${SQUID_CONF:-/etc/squid/squid.conf}"
squid_open() {
  local want="$1"
  if [ ! -f "$SQUID_CONF" ]; then
    echo "  note: $SQUID_CONF not found; relay not toggled"
    return 0
  fi
  case "$want" in
    on)
      if ! grep -q 'ARTEX-OPEN-ALLOW' "$SQUID_CONF"; then
        cp -a "$SQUID_CONF" "$SQUID_CONF.bak.$(date -u +%Y%m%dT%H%MZ)"
        sed -i '/^http_access deny all/i http_access allow all  # ARTEX-OPEN-ALLOW' "$SQUID_CONF"
        echo "  relay: added http_access allow all (before deny all)"
      fi ;;
    off)
      if grep -q 'ARTEX-OPEN-ALLOW' "$SQUID_CONF"; then
        sed -i '/^http_access allow all  # ARTEX-OPEN-ALLOW/d' "$SQUID_CONF"
        echo "  relay: removed open-mode allow"
      fi ;;
  esac
  if command -v squid >/dev/null 2>&1; then
    squid -k reconfigure >/dev/null 2>&1 || echo "  note: squid reconfigure failed; check $SQUID_CONF"
  fi
}

if [ "$OPEN" -eq 1 ] && [ -n "$PROFILE" ]; then
  die "--open and --profile are different postures; pick one"
fi

ALLOW_DIR="nftables"
if [ -n "$PROFILE" ]; then
  ALLOW_DIR="nftables/profiles/$PROFILE"
  [ -d "$ALLOW_DIR" ] || die "profile not found: $ALLOW_DIR (see --list-profiles)"
fi

[ "$(id -u)" -eq 0 ] || die "needs root (nftables)"
command -v nft >/dev/null || die "nft not installed"

if [ "$REVERT" -eq 1 ]; then
  say "revert: removing table inet artex and inet artex_baseline"
  nft delete table inet artex 2>/dev/null \
    && echo "  artex removed — containers fall back to the host's default routes" \
    || echo "  artex not present"
  nft delete table inet artex_baseline 2>/dev/null \
    && echo "  baseline removed" \
    || echo "  baseline not present"
  squid_open off
  exit 0
fi

# ---------------------------------------------------------------- open mode
# No client scope. Full public egress, with the four things that are never
# legitimate still closed (metadata, RFC1918 outside the lab, host services,
# and a log line for everything dropped).
if [ "$OPEN" -eq 1 ]; then
  OPEN_FILE="nftables/artex-baseline.nft"
  [ -f "$OPEN_FILE" ] || die "run from the repo root ($OPEN_FILE not found)"
  OPEN_RENDER="$(mktemp)"
  trap 'rm -f "$OPEN_RENDER"' EXIT
  sed -e "s#172\.28\.0\.0/24#$SUBNET#g" -e "s/172\.28\.0\.1/$GATEWAY/g" "$OPEN_FILE" > "$OPEN_RENDER"

  say "mode=open subnet=$SUBNET"
  echo "  egress    : all public IPv4"
  echo "  closed    : 169.254.0.0/16, 100.100.100.200, 192.0.0.192"
  echo "             10/8, 172.16/12, 192.168/16 outside the lab"
  echo "             lab -> host except tcp/3128 and tcp+udp/53"
  echo "  removed   : table inet artex (the per-client scope layer)"

  if [ "$DRY" -eq 1 ]; then
    say "syntax check"
    nft -c -f "$OPEN_RENDER" && echo "  ruleset parses"
    echo "  relay would get: http_access allow all  # ARTEX-OPEN-ALLOW  ($SQUID_CONF)"
    echo
    echo "dry run: nothing applied."
    exit 0
  fi

  nft -f "$OPEN_RENDER"
  nft add element inet artex_baseline lab_net "{ $SUBNET }"
  if nft delete table inet artex 2>/dev/null; then
    echo "  scope layer removed"
  fi
  squid_open on
  cat <<EOF

Open mode is live. The application's own scope guard is now the only thing
deciding what the agent may attack. Verify it before the first real packet:

  docker exec artex-artex-1 <the guard's out-of-scope test>
  # and watch: journalctl -k -f | grep ARTEX-BASE

Back to scoped mode:  sudo ./scripts/egress-apply.sh [--profile <name>]
Close everything:     sudo ./scripts/egress-apply.sh --revert
EOF
  exit 0
fi

[ -f "$NFT_FILE" ] || die "run from the repo root ($NFT_FILE not found)"

# The ruleset hard-codes the gateway for the proxy path. If you change the compose
# subnet, change both, or the firewall silently stops applying to your containers.
grep -q "$DEFAULT_GATEWAY" "$NFT_FILE" || die "gateway literal $DEFAULT_GATEWAY not found in $NFT_FILE — ruleset edited?"
grep -q "$SUBNET" "$NFT_FILE" || echo "note: $SUBNET not literal in ruleset (set at apply time)"
if [ "$GATEWAY" != "$DEFAULT_GATEWAY" ]; then
  echo "note: rendering ruleset for gateway $GATEWAY (not the hardened compose's $DEFAULT_GATEWAY)"
fi
NFT_RENDER="$(mktemp)"
trap 'rm -f "$NFT_RENDER"' EXIT
sed "s/172\.28\.0\.1/$GATEWAY/g" "$NFT_FILE" > "$NFT_RENDER"

read_set() {
  # A comment-only file (the .example contents) makes every grep in the
  # pipeline return 1. Under `set -o pipefail` that aborted the whole script
  # with no message, which is a bad way to find out your scope file is empty.
  local f="$1" out=""
  [ -f "$f" ] || { printf ''; return 0; }
  out=$(grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
        | sort -u | paste -sd, -) || true
  printf '%s' "$out"
}

SCOPE="$(read_set "$ALLOW_DIR/scope.allow")"
EDGE="$(read_set "$ALLOW_DIR/edge.allow")"
LLM="$(read_set "$ALLOW_DIR/llm.allow")"
DNS="$(read_set "$ALLOW_DIR/resolvers.allow")"

if [ -z "$DNS" ]; then
  echo "WARN: $ALLOW_DIR/resolvers.allow is empty — the lab will have no DNS."
  echo "      If your LLM endpoint hostname is resolved inside the container, calls will fail."
fi

say "mode=$MODE subnet=$SUBNET profile=${PROFILE:-<default>}"
printf '  in_scope : %s\n' "${SCOPE:-<empty>}"
printf '  cdn_edge : %s\n' "${EDGE:-<none>}"
printf '  llm_api  : %s\n' "${LLM:-<none>}"
printf '  resolvers: %s\n' "${DNS:-<empty>}"

if [ "$MODE" = "proxy" ] && [ -z "$LLM" ]; then
  echo "  (proxy mode: 443 to the open internet is NOT allowed; only $GATEWAY:3128)"
fi

if [ "$DRY" -eq 1 ]; then
  say "syntax check"
  nft -c -f "$NFT_RENDER" && echo "  ruleset parses"
  echo
  echo "dry run: nothing applied."
  exit 0
fi

# ---------------------------------------------------------------- load
say "loading ruleset (sets start empty => default deny)"
nft -f "$NFT_RENDER"
squid_open off   # a scoped apply must not leave the relay in open mode

add_elements() {
  local set="$1" list="$2"
  [ -z "$list" ] && return 0
  nft add element inet artex "$set" "{ $list }"
}

add_elements lab_net   "$SUBNET"
add_elements in_scope  "$SCOPE"
add_elements cdn_edge  "$EDGE"
add_elements llm_api   "$LLM"
add_elements resolvers "$DNS"

say "result"
nft list table inet artex | sed -n '1,40p'

if [ -z "$SCOPE" ]; then
  cat <<'EOF'

NOTE: in_scope is empty. The lab can reach nothing except the DB and the proxy.
      Fill scope.allow in the active allow-dir from the signed scope document, then re-run.
      Default dir: nftables/   Profile dir: nftables/profiles/<name>/
EOF
fi

if [ "$MODE" = "proxy" ]; then
  cat <<EOF

NEXT: the relay must be running, or every model call fails closed.
  sudo apt install squid && sudo cp proxy/squid.conf /etc/squid/squid.conf
  sudo systemctl restart squid
  curl -x http://$GATEWAY:3128 -sS -o /dev/null -w '%{http_code}\n' https://api.deepseek.com/v1/models

And confirm the deny actually denies, from a container on the lab network:
  docker run --rm --network artex-hardened_lab curlimages/curl:latest \\
    -sS --max-time 5 http://198.51.100.7/ || echo BLOCKED
EOF
fi
