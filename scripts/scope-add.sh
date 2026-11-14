#!/usr/bin/env bash
# Add ONE host to an engagement profile's scope, with evidence, a blast-radius
# number, and the two-layer update (kernel set + relay IP literal) in one step.
#
# This is the "take any assignment" tool. It is deliberately not a "widen to a
# provider" tool: anything larger than a /24 needs --allow-large, and the delta is
# printed every time so the number is impossible to miss.
#
# Usage:
#   ./scripts/scope-add.sh --profile acme-2026-11 203.0.113.10/32 \
#       --evidence "prod web; cert SAN acme.com; RDAP netblock client-owned"
#   sudo ./scripts/scope-add.sh --profile acme-2026-11 203.0.113.10/32 \
#       --evidence "..." --apply
#   ./scripts/scope-add.sh --profile acme-2026-11 203.0.113.0/24 \
#       --evidence "..." --allow-large --dry-run
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE=""
CIDR=""
EVIDENCE=""
APPLY=0
ALLOW_LARGE=0
DRY=0

die() { printf '\033[31mREFUSED\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    --evidence) EVIDENCE="${2:-}"; shift 2 ;;
    --evidence=*) EVIDENCE="${1#*=}"; shift ;;
    --apply) APPLY=1; shift ;;
    --allow-large) ALLOW_LARGE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown arg: $1" ;;
    *) [ -z "$CIDR" ] || die "one CIDR per invocation"; CIDR="$1"; shift ;;
  esac
done

[ -n "$CIDR" ] || die "no CIDR given"
[ -n "$EVIDENCE" ] || die "--evidence is required; an unevidenced widening is an unauthorised one"
case "$EVIDENCE" in
  todo|TODO|test|TBD|tbd|"") die "--evidence must say HOW you know the host is the client's" ;;
esac

ALLOW_DIR="nftables"
[ -n "$PROFILE" ] && ALLOW_DIR="nftables/profiles/$PROFILE"
[ -d "$ALLOW_DIR" ] || die "profile not found: $ALLOW_DIR"
SCOPE="$ALLOW_DIR/scope.allow"
[ -f "$SCOPE" ] || die "missing $SCOPE"

# ---- validate + measure, in python (ipaddress does the arithmetic) ----------
MEASURE="$(python3 - "$CIDR" "$SCOPE" <<'PY'
import sys, re, ipaddress

cidr, path = sys.argv[1], sys.argv[2]
try:
    net = ipaddress.ip_network(cidr, strict=False)
except ValueError as e:
    print(f"BAD parse: {e}"); sys.exit(3)
if net.version != 4:
    print("BAD only IPv4 is supported"); sys.exit(3)

def span(tok):
    m = re.fullmatch(r'([0-9.]+)(?:/(\d{1,2}))?(?:-([0-9.]+))?', tok.strip())
    if not m:
        return None
    base, plen, last = m.groups()
    try:
        if plen is None and last is None:
            a = int(ipaddress.ip_address(base)); return a, a
        if plen is not None:
            n = ipaddress.ip_network(tok.strip(), strict=False)
            return int(n.network_address), int(n.broadcast_address)
        a = ipaddress.ip_address(base)
        b = last if last.count('.') == 3 else f"{base.rsplit('.',1)[0]}.{last}"
        b = ipaddress.ip_address(b)
        return int(a), int(b)
    except ValueError:
        return None

total = 0
spans = []
for line in open(path):
    line = line.split('#', 1)[0].strip()
    if not line:
        continue
    tok = line.split()[0]
    s = span(tok)
    if s:
        spans.append(s)
        total += s[1] - s[0] + 1

lo, hi = int(net.network_address), int(net.broadcast_address)
covered = any(s <= lo and hi <= e for s, e in spans)
exact = any(s == lo and e == hi for s, e in spans)
delta = 0 if covered else (hi - lo + 1)

print(f"CIDR_OUT={net.with_prefixlen}")
print(f"PLEN={net.prefixlen}")
print(f"COUNT={hi - lo + 1}")
print(f"TOTAL={total}")
print(f"DELTA={delta}")
print(f"COVERED={int(covered)}")
print(f"EXACT={int(exact)}")
print(f"AFTER={total + delta}")
if total:
    print(f"PCT={(delta / total) * 100:.4f}")
else:
    print("PCT=inf")
PY
)" || die "CIDR rejected"

get() { printf '%s\n' "$MEASURE" | sed -n "s/^$1=//p"; }
case "$MEASURE" in BAD*) die "${MEASURE#BAD }" ;; esac

CIDR_OUT="$(get CIDR_OUT)"
[ -n "$CIDR_OUT" ] && CIDR="$CIDR_OUT"

PLEN="$(get PLEN)"; COUNT="$(get COUNT)"; TOTAL="$(get TOTAL)"
DELTA="$(get DELTA)"; COVERED="$(get COVERED)"; EXACT="$(get EXACT)"
AFTER="$(get AFTER)"; PCT="$(get PCT)"

if [ "$COVERED" -eq 1 ]; then
  echo "already covered: $CIDR is inside an existing entry in $SCOPE"
  echo "  in_scope total stays $(printf '%s' "$TOTAL" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta') addresses"
  exit 0
fi

if [ "$PLEN" -lt 24 ] && [ "$ALLOW_LARGE" -ne 1 ]; then
  die "$CIDR is a /$PLEN = $(printf '%s' "$COUNT" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta') addresses.
  /32 preferred, /24 is the ceiling for a shared-ASN host. A larger prefix is only
  acceptable for a client-owned netblock proven by RDAP. Re-run with --allow-large
  and put the proof in --evidence if that is what this is."
fi

if [ "$DELTA" -ge 65536 ] && [ "$ALLOW_LARGE" -ne 1 ]; then
  die "this adds $DELTA addresses (>= a /16). That is a provider, not a target.
  Re-run with --allow-large only if the scope document says so in writing."
fi

h() { printf '%s' "$1" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'; }
UNIT=addresses; [ "$COUNT" -eq 1 ] && UNIT=address

echo "profile : ${PROFILE:-<default>}"
echo "adding  : $CIDR   ($(h "$COUNT") $UNIT)"
echo "evidence: $EVIDENCE"
echo "scope   : $(h "$TOTAL") -> $(h "$AFTER") addresses  (+$(h "$DELTA"), +${PCT}%)"

if [ "$DRY" -eq 1 ]; then
  echo
  echo "dry run: nothing written, nothing applied."
  exit 0
fi

STAMP="$(date -u +%Y%m%dT%H%MZ)"
cp "$SCOPE" "$SCOPE.bak.$STAMP"
printf '%s   # %s — %s\n' "$CIDR" "$(date -u +%Y-%m-%d)" "$EVIDENCE" >> "$SCOPE"
echo "appended to $SCOPE (backup: $(basename "$SCOPE").bak.$STAMP)"

if [ "$APPLY" -ne 1 ]; then
  cat <<EOF

Not applied. To make it live:
  ./scripts/render-squid-scope.sh${PROFILE:+ --profile $PROFILE}
  sudo nft add element inet artex in_scope { $CIDR }    # live, no table reload
  sudo squid -k reconfigure                             # reloads ACLs
  ./scripts/render-squid-scope.sh${PROFILE:+ --profile $PROFILE} --check
Or re-run this with --apply (needs root).
EOF
  exit 0
fi

[ "$(id -u)" -eq 0 ] || die "--apply needs root"
./scripts/render-squid-scope.sh ${PROFILE:+--profile "$PROFILE"}
nft add element inet artex in_scope "{ $CIDR }"
squid -k reconfigure
echo "live: $CIDR added to in_scope; relay ACL reloaded"
