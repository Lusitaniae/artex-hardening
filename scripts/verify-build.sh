#!/usr/bin/env bash
# Build ARTEX from a pinned commit, locally, and emit an attestation.
#
# What this does NOT do: prove the code is safe. It proves which bytes you built
# from, on which date, with which tool versions. That is the only claim a signature
# can honestly make. See README §6 for the audit that has to happen alongside it.
#
# Usage:
#   COMMIT=<full-40-char-sha> ./scripts/verify-build.sh
#   UPSTREAM_URL=https://github.com/Autumn-27/ARTEX.git COMMIT=... ./scripts/verify-build.sh
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/jiwoochris/artex-global.git}"
COMMIT="${COMMIT:?set COMMIT to a full 40-character commit sha}"
WORKDIR="${WORKDIR:-build}"
IMAGE_TAG="${IMAGE_TAG:-artex-hardened:${COMMIT:0:12}}"
UPSTREAM_URL="${UPSTREAM_URL:-}"
ARTIFACT_DIR="artifacts"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
warn() { printf '\033[33mWARN\033[0m %s\n' "$*"; }
die() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- sanity
[ ${#COMMIT} -eq 40 ] || die "COMMIT must be a full 40-char sha, got '${COMMIT}'"
command -v git >/dev/null || die "git not found"
command -v docker >/dev/null || die "docker not found"
mkdir -p "$ARTIFACT_DIR"

# ---------------------------------------------------------------- fetch
say "fetch $REPO_URL @ $COMMIT"
if [ ! -d "$WORKDIR/.git" ]; then
  git clone --filter=blob:none --no-checkout "$REPO_URL" "$WORKDIR"
fi
git -C "$WORKDIR" fetch --quiet origin
git -C "$WORKDIR" cat-file -e "${COMMIT}^{commit}" 2>/dev/null \
  || die "commit $COMMIT not present in $REPO_URL"
git -C "$WORKDIR" -c advice.detachedHead=false checkout --quiet "$COMMIT"

SRC_SHA="$(git -C "$WORKDIR" rev-parse HEAD)"
[ "$SRC_SHA" = "$COMMIT" ] || die "checked out $SRC_SHA, expected $COMMIT"

# ---------------------------------------------------------------- provenance
say "provenance"
META_AUTHOR="$(git -C "$WORKDIR" log -1 --format='%an <%ae>')"
META_DATE="$(git -C "$WORKDIR" log -1 --format='%ci')"
META_SUBJ="$(git -C "$WORKDIR" log -1 --format='%s')"
META_SIG="$(git -C "$WORKDIR" log -1 --format='%G?')"
TREE_SHA="$(git -C "$WORKDIR" ls-tree -r HEAD | sha256sum | cut -d' ' -f1)"
PARENT_AGE="$(( ( $(date +%s) - $(git -C "$WORKDIR" log -1 --format='%ct') ) / 86400 ))"

printf '  commit      %s\n' "$SRC_SHA"
printf '  author      %s\n' "$META_AUTHOR"
printf '  date        %s (%s days ago)\n' "$META_DATE" "$PARENT_AGE"
printf '  subject     %s\n' "$META_SUBJ"
printf '  signature   %s\n' "$META_SIG"
printf '  tree sha256 %s\n' "$TREE_SHA"

[ "$META_SIG" = "N" ] && warn "commit is not signed — you are trusting an unsigned object"
[ "$PARENT_AGE" -lt 30 ] && warn "commit is ${PARENT_AGE} days old — expect churn; re-audit if you pin later"

if [ -n "$UPSTREAM_URL" ]; then
  say "diff against upstream"
  if git -C "$WORKDIR" remote get-url upstream >/dev/null 2>&1; then
    git -C "$WORKDIR" remote set-url upstream "$UPSTREAM_URL"
  else
    git -C "$WORKDIR" remote add upstream "$UPSTREAM_URL"
  fi
  if git -C "$WORKDIR" fetch --quiet upstream 2>/dev/null; then
    git -C "$WORKDIR" --no-pager diff --stat upstream/HEAD..HEAD | tail -40
    echo
    warn "review every hunk above. expected: web/ i18n, agent/prompt.go, docs, .env.example"
  else
    warn "upstream unreachable — no baseline to diff against. This is the core trust gap."
  fi
else
  warn "UPSTREAM_URL unset: skipping diff. You have no fork-vs-upstream evidence."
fi

# ---------------------------------------------------------------- build
say "build (no cache, from $SRC_SHA)"
export SOURCE_DATE_EPOCH="$(git -C "$WORKDIR" log -1 --format='%ct')"
BUILD_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker build --no-cache -f "$WORKDIR/Dockerfile" -t "$IMAGE_TAG" "$WORKDIR"
BUILD_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$IMAGE_TAG")"
IMAGE_SIZE="$(docker image inspect -f '{{.Size}}' "$IMAGE_TAG")"

# ---------------------------------------------------------------- sbom + scan
say "sbom / scan (optional)"
if command -v syft >/dev/null 2>&1; then
  syft "$IMAGE_TAG" -o spdx-json > "$ARTIFACT_DIR/sbom.spdx.json"
  echo "  sbom -> $ARTIFACT_DIR/sbom.spdx.json"
else
  warn "syft not installed: no SBOM. Install it if you intend to publish this build."
fi
if command -v trivy >/dev/null 2>&1; then
  trivy image --quiet --severity HIGH,CRITICAL "$IMAGE_TAG" > "$ARTIFACT_DIR/trivy.txt" 2>&1 || true
  echo "  scan -> $ARTIFACT_DIR/trivy.txt ($(grep -c '^Total:' "$ARTIFACT_DIR/trivy.txt" || true) rows)"
else
  warn "trivy not installed: no CVE scan."
fi

# ---------------------------------------------------------------- attestation
ATT="$ARTIFACT_DIR/build-attestation.txt"
say "attestation -> $ATT"
{
  echo "ARTEX BUILD ATTESTATION"
  echo "generated:            $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "builder host:         $(hostname)"
  echo "builder kernel:       $(uname -sr)"
  echo "docker:               $(docker version -f '{{.Server.Version}}' 2>/dev/null || echo unknown)"
  echo "go:                   $(go version 2>/dev/null || echo 'n/a (built in container)')"
  echo
  echo "source repo:          $REPO_URL"
  echo "source commit:        $SRC_SHA"
  echo "source commit author: $META_AUTHOR"
  echo "source commit date:   $META_DATE"
  echo "commit signature:     $META_SIG"
  echo "tree sha256:          $TREE_SHA"
  echo "source_date_epoch:    $SOURCE_DATE_EPOCH"
  echo
  echo "image tag:            $IMAGE_TAG"
  echo "image id:             $IMAGE_ID"
  echo "image size bytes:     $IMAGE_SIZE"
  echo "build window:         $BUILD_START .. $BUILD_END"
  echo
  echo "ATTESTED BY THIS FILE: the image above was built from the commit above,"
  echo "on the host above, at the time above."
  echo "NOT ATTESTED: that the code is safe, correct, or free of malicious logic."
  echo "That requires the manual audit in README section 6."
} | tee "$ATT"

echo
echo "Next:"
echo "  1. audit the diff (README §6). Do not skip because the build succeeded."
echo "  2. set ARTEX_IMAGE=$IMAGE_TAG in .env.hardened"
echo "  3. sign it if you intend to distribute:  cosign sign --key cosign.key $IMAGE_ID"
