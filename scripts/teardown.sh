#!/usr/bin/env bash
# Destroy the engagement environment and prove it is gone.
#
# Assumes the box is disposable. If it is not, this script is the wrong shape for
# you — you need a per-engagement VM, not a reused host.
#
# Usage: ./scripts/teardown.sh --confirm
set -euo pipefail

ENV_FILE=".env.hardened"
COMPOSE_FILE="docker-compose.hardened.yml"

[ "${1:-}" = "--confirm" ] || {
  echo "This destroys containers, the Postgres volume (credentials, loot, target graph)"
  echo "and the firewall table. Re-run with:  $0 --confirm"
  exit 2
}

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "compose down (volumes included)"
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true

say "firewall state"
if nft list table inet artex >/dev/null 2>&1; then
  nft delete table inet artex
  echo "  nft table inet artex removed"
else
  echo "  no nft table present"
fi

say "verify volumes are gone"
LEFT="$(docker volume ls -q | grep -E 'artex-hardened_(db_data|artex_data|artex_keys)' || true)"
if [ -z "$LEFT" ]; then
  echo "  no artex volumes remain on this host"
else
  echo "  STILL PRESENT: $LEFT"
  echo "  docker volume rm $LEFT"
fi

say "verify network is gone"
docker network inspect artex-hardened_lab >/dev/null 2>&1 \
  && echo "  STILL PRESENT: artex-hardened_lab" \
  || echo "  network removed"

cat <<'EOF'

--------------------------------------------------------------------
MANUAL CHECKLIST — none of these are covered by the script above
--------------------------------------------------------------------
[ ] Provider snapshots / automatic backups of this VM deleted (a snapshot
    of a disk containing client credentials is still client credentials)
[ ] Block storage detached AND deleted, not just unmounted
[ ] DNS records for any tunnel endpoint removed
[ ] squid logs (/var/log/squid/artex-access.log) handled per the client's
    retention terms — they contain prompt summaries and provider domains
[ ] Evidence/report exported to the client's agreed location, then local
    copies destroyed; confirm deletion in writing if the contract requires it
[ ] LLM provider request logs: retention is set by THEM. Note in the report
    which provider, which retention window, and whether ZDR was active
[ ] Scope document and written authorisation archived with the deliverable
[ ] SSH keys / API keys used for this engagement revoked or rotated
[ ] If the VM is reused: rebuild from image. Do not scrub a used host.
EOF
