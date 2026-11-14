#!/usr/bin/env bash
# Resolve image tags to digest-pinned references.
#
# Tags move. Digests don't. Every image in this stack must be pinned, or "what
# exactly did I run on that engagement" has no answer six weeks later.
#
# Usage: ./scripts/pin-digests.sh [image ...]
set -euo pipefail

resolve() {
  local ref="$1"
  if command -v skopeo >/dev/null 2>&1; then
    skopeo inspect "docker://${ref}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Digest"])'
  elif command -v crane >/dev/null 2>&1; then
    crane digest "$ref"
  elif docker buildx version >/dev/null 2>&1; then
    docker buildx imagetools inspect "$ref" | awk '/^Digest:/{print $2; exit}'
  else
    echo "ERROR: need skopeo, crane, or docker buildx" >&2
    return 1
  fi
}

pin() {
  local ref="$1" name tag digest
  name="${ref%@*}"
  tag="${name##*:}"
  [ "$tag" = "$name" ] && tag="latest"
  digest="$(resolve "$ref")" || { echo "FAILED  $ref" >&2; return 1; }
  printf '%s@%s\n' "${name%%:*}:${tag}" "$digest"
}

echo "# digest-pinned references (generated $(date -u +%Y-%m-%dT%H:%M:%SZ))"
echo "# paste into .env.hardened as ARTEX_IMAGE / POSTGRES_IMAGE"

if [ "$#" -eq 0 ]; then
  set -- postgres:17-alpine
fi

for ref in "$@"; do
  pin "$ref"
done

cat <<'EOF'

# ARTEX_IMAGE is the image YOU build (scripts/verify-build.sh), tagged by commit.
# It has no registry digest until you push it. Tag it by commit and record the
# local image ID in artifacts/build-attestation.txt — that is your pin.
EOF
