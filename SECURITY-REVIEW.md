# ARTEX fork — operator-impact review

**Subject:** the ARTEX build deployed from `/root/src/ARTEX` on `<deploy-host>`.
**Question:** does anything in this build act against the operator — malware, telemetry,
phone-home, or data exfiltration?
**Answer:** no operator-directed behaviour was found. This document is the evidence for
that sentence, and the list of things it does *not* cover.

Reviewed 2026-11-14. Read-only: no file on the deployment host was modified.

---

## 1. What exactly was reviewed

| Item | Value |
|---|---|
| Fork | `github.com/BaaRai/ARTEX` (`origin/main` = `a908e1e`, release v0.5.1) |
| Deployed source | `origin/main` + 10 local commits = `b95a57f`. The published repo has one further commit, `316aa94` (release-workflow neutralisation, §F6), which is not part of the deployed build |
| Source tree hash | `2bd1acc4ca4bcb821a4a5add67ebd3876b647312` — reproduced byte-for-byte by applying `patches/0001…0010` to `a908e1e`. (Committed HEAD alone is `a8f3b53` = tree `d06c63de`; the 10th commit is the uncommitted deployment delta that was present when the image was built.) |
| Running image | `artex:local-20261109` = `sha256:0bd35306…448cc89f`, built 2026-11-09T03:55:23Z |
| Database | `postgres:16-alpine` |
| Local commits | 10, all build/packaging/UI. None touch `agent/`, `llm/`, `tool/`, `intercept/`, `server/server.go` routing, or any network path |
| License | AGPL-3.0 |

The 10 local commits are published as `patches/0001…0010` so the deployed tree is
reconstructible from the fork without trusting this document. Provenance check: the
`Dockerfile` was last modified 2026-11-09T03:43:23Z; the running image was built
2026-11-09T03:55:23Z, i.e. after it — so the image does contain this source, including the
WPScan stage.

## 2. Verdict

| Claim | Evidence | Confidence |
|---|---|---|
| No self-updater / phone-home loop | `selfupdate/` does not exist in the tree. `update.sh` is interactive `git pull --ff-only` + rebuild, never invoked at runtime. Compose sets `pull_policy: never` | high |
| No telemetry or analytics SDK | No analytics/sentry/segment/posthog dependency in `go.mod`, no such host in any source or config file | high |
| No hardcoded exfiltration destination | Every non-test network primitive takes a config- or user-supplied URL (6 files, §4). Only hardcoded hosts are opt-in IM adapters and model-provider APIs | high |
| No obfuscated payload | No base64 literal >200 chars anywhere in Go source; no `sh -c` wrapper around `curl`/`wget`; no `ADD <url>` in the Dockerfile | high |
| Dependency patch is a republish, not a modification | `replace github.com/Autumn-27/norma => github.com/BaaRai/Norma v0.4.4`; `diff -r` against `Autumn-27/norma@v0.4.4` is **empty, byte-identical** | high |
| Egress in the observed window went only to allowlisted or denied destinations | `artex-access.log`, §5 | medium — one-day window |
| Build is reproducible from source | tree hash match; bases digest-pinned; every downloaded tool SHA-256-verified; `pip --require-hashes`; `npm ci --ignore-scripts` | high |
| No operator-directed dependency | §7 — 4 advisories across 356 packages, all parser/decompression classes; none is a network callback, persistence mechanism, or post-install hook | medium |
| The deployed commit passes upstream's own test suite | GitHub Actions `ci` run 43564726771 on `b95a57f` — success, 9m47s (Go tests against a real Postgres service) | high |

## 3. Findings

### F1 — Application-level scope enforcement was removed (medium, operator-facing)

`guard/guard.go` header:

> The RoE authorization-scope mechanism was removed; a replacement may be added later.
> Destructive/exfil gating is no longer hard-coded here — it lives in the DB intercept
> rules (seeded as ordinary `[built-in]` rules, so users can disable or delete them).

Consequence for an operator: the agent's safety rails are **rows in Postgres**, editable
from the UI. The only non-bypassable boundary is the nftables egress allowlist. This is
documented as assumption **A7 = false** in `README.md`; it is repeated here because it is
the single most load-bearing fact about running this tool, and it is not malware — it is
a deliberate design change that moves risk onto the operator.

Mitigation already deployed: `nftables/artex-egress.nft` default-deny, with `company_scope`
treated as advisory only.

### F2 — `mcphttp` has no internal-address guard (low–medium)

`notify/http.go` installs a `Control` hook (`blockInternalDial`) so a webhook cannot be
pointed at loopback/RFC1918/link-local. `mcphttp/client.go` makes four equivalent
requests (`NewRequestWithContext` at lines 146/469/544, `NewRequest` at 419) and installs
**no** such guard.

Impact is bounded: MCP server URLs are operator-supplied, and container egress is
default-deny, so `169.254.169.254` is unreachable at the kernel (`artex-meta-block`) as
well. But the two packages disagree, and if the allowlist ever admits an internal range
the MCP path becomes the way in. Fix: reuse `blockInternalDial` in `mcphttp`.

### F3 — `Access-Control-Allow-Origin: *` on the authenticated API (informational)

`server/server.go:4026` sets `*` unconditionally. Not currently exploitable:

- no `Access-Control-Allow-Credentials`, so the `artex_token` cookie cannot be read cross-origin;
- `Allow-Headers` is `Content-Type` only, so a cross-origin preflight cannot send `Authorization`.

It is still the wrong default for an authenticated API behind a loopback-only listener.
Fix: echo an origin allowlist, or drop CORS entirely for the single-origin UI.

### F4 — `api.pdtm.sh` is a live runtime update channel (low)

Observed 15 times in the egress log, correctly `TCP_DENIED/403`. It is consistent with
ProjectDiscovery's tool manager being invoked by the bundled OSS tooling. Nothing in the
ARTEX tree references it. Note for future runs: if the allowlist is widened, this becomes
reachable, and it is an update fetch — i.e. remote code that is not digest-pinned at
runtime.

### F5 — The privileged dependency is fetched from a third-party mirror (informational)

`go.mod:64` redirects `github.com/Autumn-27/norma` to `github.com/BaaRai/Norma`. Content
verified identical to upstream `v0.4.4` (§2), so this is a **provenance** nit, not a code
finding: the build trusts a mirror's path for the module that holds the LLM client, tool
executor and hooks. Options: drop the `replace` and require the upstream path, or vendor
the module into the tree.

### F6 — `release.yml` made any fork the publisher of `latest` — **neutralised**

Upstream's `.github/workflows/release.yml` triggered on `push: tags: ["v*"]`: it built
5-platform release zips, cut a GitHub Release, and pushed multi-arch images to `ghcr.io`
tagged **`latest`**, using tag-pinned (not SHA-pinned) actions.

In the published fork this is fixed at `316aa94` — the trigger is now `workflow_dispatch`
only, so nothing publishes on a tag. The deployed build is the parent of that commit and is
unaffected. Remaining optional hardening: pin each `uses:` to a commit SHA.

## 4. Network surface, file by file

Six non-test Go files hold network primitives. All take a caller-supplied URL:

| file | line | URL source | internal-address guard |
|---|---|---|---|
| `server/customtool.go` | 437 | user-defined tool | no (operator-authored) |
| `mcphttp/client.go` | 146/419/469/544 | operator-configured MCP server | **no — F2** |
| `enrich/enrich.go` | 229 | config | no |
| `notify/http.go` | 164 | DB `notification_channels.config` | yes (`blockInternalDial`) |
| `notify/email.go` | — | DB SMTP config | n/a |
| `server/server_mgmt.go` | — | admin API (LLM pool) | n/a |

`intercept/` contains no logging of `Authorization`/`Cookie` headers — the recording layer
captures bodies and metadata, not credentials.

## 5. Observed egress

`/var/log/squid/artex-access.log.1` (2026-11-13, ~20 KB, all rotations, no other source):

| destination | hits | classification |
|---|---|---|
| `<in-scope target>` | 114 | in-scope target |
| `raw.githubusercontent.com` | 17 | nuclei template fetch |
| `i.pki.goog` / `c.pki.goog` | 17 / 2 | CRL/OCSP, automatic TLS verification |
| `api.pdtm.sh` | 15 | ProjectDiscovery tool manager — **403 denied** |
| `api.deepseek.com` | 6 | configured model provider |
| `codeload.github.com` / `api.github.com` | 2 / 2 | nuclei template fetch |
| `web.archive.org` / `crt.sh` | 2 / 2 | recon data sources |
| `publicsuffix.org` | 1 | Go PSL library list refresh |

Zero unexplained destinations. Everything either matched an allowlist entry or was refused.

**Limits of this evidence:** the retained log covers roughly one day, and direct egress is
*default-denied* rather than *logged* — a packet that bypassed squid would have been
dropped, not recorded. Container-level capture (`traffic/`, port 8788) covers the
engagement window. The claim this supports is:

> *"Over the observed window, every outbound connection matched an allowlist entry or was
> denied. Direct egress was default-denied at the kernel."*

It is not: *"this build cannot exfiltrate data."*

## 6. What this review cannot establish

1. **Provenance against upstream.** `Autumn-27/ARTEX` is unreachable. There is no baseline
   to diff, so nothing here distinguishes "the fork added this" from "upstream already had
   it". The fork has a ~96% fork-to-star ratio and appeared after press reporting tied
   upstream to financial-sector data theft — this review says nothing about that.
2. **Intent.** Everything above is *capability and observed behaviour*. A build can be
   clean in every check here and still be malicious on a path not exercised.
3. **The model provider.** DeepSeek receives target data under its own terms (ZDR is a
   contractual claim, not a verifiable control). See `STATUS.md` §7.3.
4. **Reachability.** §7 is version-level, not symbol-level. No `govulncheck` call-graph
   pass has been run, so an advisory present in a dependency may not be reachable.

## 7. Supply chain

`tools/sbom-scan.py` queries the OSV database for every package in the build: 53 Go
modules (`go.mod`), 68 PyPI distributions (the hash-pinned bbot lock), and 235 Debian
bookworm packages read from the running image. Reproduce with
`ARTEX_HOST=root@<deploy-host> ./tools/sbom-scan.py`.

**Go and PyPI** — 4 modules carry advisories:

| ecosystem | package | version | advisory |
|---|---|---|---|
| Go | `github.com/klauspost/compress` | v1.18.6 | GO-2026-5841 (s2 OOB read), GO-2026-6865 (panic on two-block frames), GHSA-259r-337f-4rfw (integer overflow → OOB write) |
| Go | `github.com/andybalholm/brotli` | v1.2.1 | GO-2026-6888 (excessive allocation on crafted streams) |
| Go | `golang.org/x/crypto` | v0.58.0 | GO-2026-5932 (`openpgp` unmaintained — only if that package is imported) |
| PyPI | `dnspython` | 2.8.0 | GHSA-vvf4-9x63-8xvv, GHSA-45c3-73f7-pv4m (excessive CPU/memory in name parsing) |

These are **module-level**, not call-graph: OSV says the version is affected, not that the
vulnerable symbol is reachable. Two of them are nonetheless worth taking seriously here,
because of what this tool *does*: an agent that scans targets parses attacker-controlled
bytes by design. `brotli` and `compress/s2` sit on the HTTP-response path, and `dnspython`
sits on the DNS path that bbot drives. A crafted response from an in-scope host reaches
them. That is a different risk profile from a web app behind a form.

**Debian** — 142 tracker rows, and they should not be read as 142 vulnerabilities. OSV's
Debian data records security-tracker entries; an entry carrying `introduced: 0` and no
`fixed` event — the ordinary no-DSA case — is reported as affecting every version. Verified
on one: `DEBIAN-CVE-2024-2379` for `curl` asserts `introduced: 0` for `Debian:12` with no
fix recorded, although bookworm shipped a fix in a point release. That is the mechanism
behind most of the 142.

**Verdict:** nothing operator-directed, and nothing that changes §2. Actionable next step,
in priority order: `govulncheck` for call-graph precision (it would clear `openpgp`
immediately), bump `klauspost/compress` past the s2 fixes, and run the base image through a
distro-aware scanner (`trivy`/`grype` with the Debian feed) rather than OSV.

## 8. Reproduce

```bash
# deployed tree, from the fork + published patches
git clone https://github.com/BaaRai/ARTEX && cd ARTEX
git checkout a908e1e && git am /path/to/patches/*.patch
git rev-parse HEAD^{tree}          # expect 2bd1acc4ca4bcb821a4a5add67ebd3876b647312

# network surface
grep -rlE 'net\.Dial|http\.NewRequest|http\.Post|exec\.Command' --include=*.go . | grep -v _test.go

# no obfuscation
grep -rnoE '"[A-Za-z0-9+/]{200,}={0,2}"' --include=*.go .

# egress, on the host
awk '{print $7}' /var/log/squid/artex-access.log | sed -E 's|^[a-z]+://||; s|:[0-9]+.*$||' | sort | uniq -c | sort -rn
```

## 9. Publishable statement

Use this, verbatim, wherever this work is shared:

> Audit of the deployed ARTEX fork (BaaRai/ARTEX `a908e1e` + 10 hardening commits, tree
> `2bd1acc4`): no self-updater, no telemetry, no hardcoded exfiltration destination, no
> obfuscated payload; the patched dependency is byte-identical to upstream; and observed
> egress matched the allowlist or was denied. **Upstream `Autumn-27/ARTEX` is unreachable,
> so this is a review of the fork's deployed surface, not a comparison against upstream —
> provenance remains unverifiable.**
