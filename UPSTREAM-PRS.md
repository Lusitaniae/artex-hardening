# Upstream PR plan — `BaaRai/ARTEX`

Status as of 2026-11-20. Base at time of writing: `ab40834` (403 commits past `v0.6.0`).
Companion documents: `SECURITY-REVIEW.md` (finding IDs F1–F6), `README.md` (baseline).

Purpose: get the generic parts of this fork into upstream so they stop being our maintenance
burden. The fork should trend toward three irreducible commits — release neutralisation,
engagement build bits, unprivileged container — not eleven.

---

## 1. Mechanics

| Item | Value |
|---|---|
| Base repo | `BaaRai/ARTEX`, branch `main` |
| PR head | `Lusitaniae/ARTEX-upstream` — a real fork created 2026-11-20, added as remote `prfork` |
| Not usable as head | `Lusitaniae/ARTEX` — standalone repo (`isFork: false`), so GitHub refuses cross-repo PRs; it stays the hardening fork |
| Author | `Pedro Gomes <pedrogomesyoo@gmail.com>`, signed (SSH). Never an engagement pseudonym |
| Branch names | `pr/<slug>`, one change per branch, based on `origin/main` |

Upstream rules (`CONTRIBUTING.md`):

- **At most 7 open PRs per contributor.** We currently use 2. Close or merge before opening more.
- **One focused change per PR.** Split independent parts; say what depends on what.
- **Describe the change**: problem, behaviour change, what was tested.
- **Vulnerabilities go through `SECURITY.md`, not a public issue.**
- Provider support stays generic (no baked vendor endpoints or vendor-specific env vars).

Extraction rule: branch from `origin/main` and re-author the change against upstream's current
files. Do **not** cherry-pick the fork's commits blindly — they assume `USER 10001`, `/home/artex`,
and a Dockerfile layout upstream does not have.

---

## 2. Status board

| # | PR | Source in fork | Size | Status |
|---|---|---|---|---|
| 1 | web: ETag + gzip + immutable caching for the embedded SPA | `8ad714c` | +306/−17, 3 files | **Open — [#404](https://github.com/BaaRai/ARTEX/pull/404)**, all checks green |
| 2 | web: logo at display size + WebP | `78d4495` | +3/−3, 7 files | **Open — [#405](https://github.com/BaaRai/ARTEX/pull/405)**, all checks green |
| 3 | build: digest-pin base images | `a1b7487`, `8566538` | — | **Covered by [#397](https://github.com/BaaRai/ARTEX/pull/397)** (draft, another contributor). Do not duplicate |
| 4 | build: bake pinned nuclei templates | `9987aae` | ~30 lines, Dockerfile | Planned — needs rework for the root runtime |
| 5 | build: pin tool SHA-256 instead of fetching `SHASUMS` | part of `175f0ab` | ~60 lines, Dockerfile | Planned — argument needed (TOFU vs pinned) |
| 6 | security: internal-address guard in `mcphttp` (F2) | none (finding) | ~40 lines + test | Planned — **private advisory first** |
| 7 | build: hashed bbot dependencies | part of `a1b7487` | +2,585 lock | Optional — expect pushback, low priority |

Deliberately not sent: §5.

---

## 3. Opened

### #404 — web: add ETag, gzip and immutable caching to the embedded SPA handler

- **Problem**: assets served from `embed.FS` have a zero modtime, so no `Last-Modified` and no
  `ETag`; every load re-downloaded ~1.55 MB. `Accept-Encoding` was ignored.
- **Change**: SHA-256 strong ETags, one-time gzip of compressible assets >1 KiB (~450 KB cache),
  `Vary: Accept-Encoding`, `gzip;q=0`, immutable `/_next/static/*`, `no-cache` for HTML.
  Stdlib only.
- **Tests**: `server/webui_assets_test.go` — validators/304, encoding negotiation, cache policy,
  range, missing asset.
- **State**: `MERGEABLE`, go (13m38s, `-race`) / go-stable / web / python / shell / reply all pass.

### #405 — web: ship the logo at display size and serve WebP when supported

- **Problem**: a 1920×1920 PNG (492 KB) displayed at 40 px and 160 px; the same file served as
  the favicon.
- **Change**: 512×512 PNG (72 KB) + 512×512 WebP (32 KB) behind `<picture>` at the three `<img>`
  sites; `app/icon.png` 192×192; add `app/apple-icon.png` 180×180.
- **Tests**: `npm run build:static`; dimensions verified; no manifest references an icon size.
- **State**: `MERGEABLE`, all checks pass.

---

## 4. Covered elsewhere — do not duplicate

**#397 — build: pin base images to multi-platform digests** (draft, `YunzhouLi-hub`)

Pins all four `FROM` lines plus the Compose Postgres image, and documents pin refreshes in
`CONTRIBUTING.md`. That is exactly our `a1b7487` + `8566538`.

Action: review it. Its `python` digest matches ours (`935c3c5b…`). Difference worth a comment:
#397 pins the **floating minor tags** (`golang:1.26-bookworm`, `node:22-bookworm-slim`), so the
digest must be refreshed whenever the tag moves; our variant pins **patch tags + digest**
(`golang:1.26.10`, `node:22.23.4`, `python:3.12.16`), which makes a digest bump an explicit
version bump. Either is correct; ours is slightly more reproducible, theirs is less churn.
Comment only if it is likely to be acted on — do not open a competing PR.

---

## 5. Planned

### 5.1 Build: bake pinned nuclei templates

- **Problem**: nuclei installs its template set on first run. With a scoped egress allowlist that
  fails softly: it logs "nuclei-templates are not installed, installing…", then "no templates
  found", and **still exits 0**. A scan can start with an empty template directory.
- **Change**: clone `nuclei-templates` at a pinned tag at build time, assert the expected commit,
  strip `.git`, assert the YAML count is >10,000. No runtime egress needed.
- **Source**: `9987aae` (20 lines).
- **Rework for upstream**: upstream installs tools in a `tools` stage and runs as root, so the
  clone target must be the runtime user's home (`/root/nuclei-templates`) or `NUCLEI_CONFIG` must
  point at it; our block assumes `/home/artex` and chowns to uid 10001. Estimate ~30 lines.
- **Verification**: build, then `nuclei -tl | wc -l` with egress denied.
- **Risk**: low. Only question is which directory upstream wants it in.

### 5.2 Build: pin tool checksums instead of fetching them

- **Problem**: upstream verifies each tool archive against `*_checksums.txt` fetched from the
  same release in the same build step. That catches corrupted or swapped downloads and moved
  tags, but it is trust-on-first-use against a compromised publisher — the checksum and the
  artifact share one trust boundary.
- **Change**: keep the same assets; replace the fetched sums with per-asset, per-arch SHA-256
  `ARG`s in the Dockerfile (12 hashes for six tools × two arches). A replaced asset then fails
  the build instead of validating itself.
- **Source**: part of `175f0ab` (our Dockerfile has this for six tools + npm globals).
- **Rework**: mechanical, against upstream's `tools` stage `fetch()` helper. ~60 lines.
- **Verification**: build both arches; intentionally corrupt one hash and confirm the build fails.
- **Risk**: low, but it adds a chore (two hashes per tool bump). Say so in the PR and offer to
  document the refresh step next to the existing pin instructions.

### 5.3 Security: internal-address guard in `mcphttp` (F2)

- **Problem**: `notify/` installs a `Control: blockInternalDial` hook so a webhook cannot be
  pointed at loopback / RFC1918 / link-local / `169.254.169.254`. `mcphttp/client.go` makes four
  equivalent requests and installs no such guard. Operator-supplied MCP URLs can therefore reach
  internal addresses; today only kernel-level egress rules stop it.
- **Change**: reuse the same guard in `mcphttp/client.go` (four `NewRequest*` sites), with an
  explicit opt-out matching `notify`'s (`ARTEX_ALLOW_LOCAL_TARGETS`-style) so local MCP servers
  keep working, plus a test mirroring `notify/ssrf_test.go`.
- **Source**: none — no commit in the fork; it is a review finding (`SECURITY-REVIEW.md` §F2).
- **Process**: `SECURITY.md` asks for a **private report**, not a public issue. File the advisory,
  then offer the patch (or let them write it and review).
- **Size**: ~40 lines + a ~60-line test.
- **Related**: upstream issue #124 (open, adversarial audit) is the natural umbrella reference.

### 5.4 Optional: hashed bbot dependencies

- **Problem**: the image runs `pip install "bbot==3.0.2"` and then `bbot --install-all-deps`,
  neither hash-pinned.
- **Change**: install bbot from a fully hashed lock (`--require-hashes`, 68 packages, amd64 +
  arm64) so a swapped or yanked dependency fails the build.
- **Source**: part of `a1b7487` (`requirements-bbot.lock`, 2,585 lines).
- **Risk**: likely rejected as a generated file upstream will not maintain. Low priority; only
  worth sending if a maintainer asks. If sent, offer the generator (`.github`-independent script)
  and the refresh command in the same PR.

---

## 6. Deliberately not sent

| Change | Why not |
|---|---|
| Run the container as `USER 10001` (`175f0ab`) | Directly contradicts `server/execpriv.go`: "the server keeps running as root", children drop to the executor. A PR would disable their new isolation rather than improve it |
| Image size cuts — drop Xvfb/mesa/llvm, vim, Node headers (`6153aaf`, `89a6384`) | Opinionated; breaks users who rely on headed browsers or the tools. The `--only-shell` + mesa purge was verified for our headless-only flow, not for everyone |
| wpscan wrapper + baked metadata DB (`2bbfcfb`) | Engagement-specific tooling, and the token-injection wrapper is a policy choice upstream has not asked for |
| bbot no-egress dry-run, static DB address (`2bbfcfb`) | Deployment-specific |
| Release workflow neutralisation (`ad8805c`) | Only meaningful for a fork. Upstream should keep publishing on tags |
| `HARDENING.md`, `scripts/verify-provenance.sh`, `scripts/bbot-module-deps.py` | Artifacts of this baseline, not of the application |

---

## 7. Checklist for each new PR

1. `gh pr list --repo BaaRai/ARTEX --state all --search "<slug>"` — no duplicate, and #397-style
   work is not already in flight.
2. Branch from `origin/main`; re-author for upstream's layout; keep it one change.
3. Run `gofmt -l .` (CI enforces it), `go test -race ./...`, and the `web` build if touched.
4. Body states problem / behaviour change / what was tested. No engagement details, no client
   names, no host names.
5. Signed commit, real author identity, ≤7 open PRs.
6. After opening: watch every check, fix on the branch, don't force-push once a reviewer has
   commented unless asked.

## 8. Open decisions

- **Do we want #397's approach or the patch-tag variant?** Decide before commenting there.
- **Is a public fork acceptable long-term?** `Lusitaniae/ARTEX-upstream` exists only to host PR
  heads. If it is dropped, the open PRs close with it.
- **Who owns the private advisory for F2?** It needs a reporter identity and a response window.
