# ARTEX — hardened deployment baseline (v0.1)

Operator runbook for running a pinned ARTEX build on a throwaway VPS, with the blast radius
contained to a network allowlist, and with a build you can actually point at and say "this
artifact came from this commit."

**Scope of this document.** It is about *containment*: what the process can reach, what it can
write, who can reach it, and what survives teardown. It is not about authorisation. Before you
run this against anything, you need written authorisation, a scope document, and a time window
that matches what you typed into `nftables/scope.allow`.

---

## 1. Threat model

What this baseline defends against:

| Threat | Control |
|---|---|
| The agent (or a prompt-injected target) pivots out of the lab | Default-deny egress on a dedicated bridge; only in-scope ranges and one LLM path |
| Cloud metadata credential theft (`169.254.169.254`) | Explicit drop, in every ruleset, before any accept |
| The web UI / traffic proxy is exposed to the internet | Loopback-only publish; input-chain drop as defence-in-depth; SSH/WireGuard only |
| First-visitor admin takeover | Loopback-only publish; one-time setup token generated at startup and printed to the container log (there is no env var for it) |
| Silent self-update pulls new code mid-engagement | `pull_policy: never`, no registry egress, digest-pinned images |
| Container escapes via caps | `cap_drop: ALL`, `no-new-privileges`, no privileged mode, pids/mem limits |
| Cross-container lateral movement (agent → Postgres) | Only 5432 accepted, everything else between lab hosts dropped |
| Disk fill from tool output / loot | log rotation, separate volume, preflight free-space gate |
| Loot surviving the engagement | Single volume, `teardown.sh` destroys it, checklist for provider-side remnants |

What it does **not** defend against, and you should stop pretending otherwise:

- **A malicious build.** If the commit you pinned contains a beacon, nothing here stops it —
  this only makes the beacon's egress *visible and mostly blocked*. Repro + signature proves
  provenance, not intent. See §6.
- **A malicious or compromised model provider.** The model sees target data. ZDR is a contract,
  not a control you can verify.
- **A wrong scope file.** The allowlist enforces exactly what you wrote. It cannot know which
  ranges you were authorised for.
- **The agent doing something legal-but-catastrophic inside scope** (deleting production data,
  locking accounts). That's what rate limits, read-only accounts and change windows are for.

---

## 2. Files

```
README.md                       this runbook
LICENSE                         MIT, for the baseline (patches/ stay AGPL-3.0)
SECURITY-REVIEW.md              operator-impact review of the deployed build (read this first)
patches/                        the 10 deployed commits as a patch series against the fork's main
.env.hardened.example           copy to .env.hardened, fill, chmod 600
docker-compose.hardened.yml     two services, one bridge, loopback publish only
nftables/
  artex-egress.nft              default-deny egress ruleset (sets populated at apply time)
  scope.allow.example           in-scope CIDRs, one per line
  scope.domains.allow.example   in-scope client names for the relay, one per line
  llm.allow.example             LLM endpoint IPs (only for --direct mode)
  resolvers.allow.example       DNS resolvers the lab may use
  profiles/                     one directory per assignment; see profiles/README.md
proxy/
  squid.conf                    domain-allowlisted egress relay (default mode)
scripts/
  pin-digests.sh                resolve image tags to sha256 digests
  verify-build.sh               clone at pinned commit, build locally, emit attestation
  egress-apply.sh               populate sets + apply nftables (--profile <engagement>)
  scope-add.sh                  one evidenced host, blast radius printed, --apply to go live
  render-squid-scope.sh         regenerate the relay's IP + domain ACLs from the active profile
  preflight.sh                  fail-fast checks before the first packet
  teardown.sh                   destroy containers, volume, firewall state
tools/
  model-ab.py                   refusal/thrash/cost harness for model selection
  sbom-scan.py                  OSV query for Go + PyPI + Debian packages in the build
```

---

## 3. Assumptions to verify before first run

This baseline was written from the fork's README, `.env.example`, `config.example.json` and
`llmpool/pool.go`. Assumptions are marked `# ASSUMPTION:` in the files. Check these against the
commit you pinned — each one is a place a fork can diverge:

| # | Assumption | Where | If wrong |
|---|---|---|---|
| A1 | Image entrypoint runs `start.sh` and honours `ARTEX_PG_DSN`, `ARTEX_LLM_*`, `ARTEX_JWT_KEY_DIR`; the listen address comes from `CMD -addr :8787` and compose publishes it on loopback | compose, env | Fall back to explicit `command:`; re-check the Dockerfile `ENTRYPOINT`/`CMD` |
| A2 | App listens on 8787 (API/UI) and 8788 (traffic-recording proxy) | compose | Adjust published port; never publish 8788 |
| A3 | Writes state to `/app/data` (`<base>/data`) and keys to `/app/keys`; both are named volumes | compose volumes | Mount both or a recreate loses the traffic index and `secret.key` |
| A4 | Postgres is reachable as a service named `db` on 5432 | compose DSN | Adjust DSN |
| A5 | `ARTEX_LLM_PROXY` accepts an HTTP forward proxy for model calls | env | Use `--direct` egress mode with pinned IPs (fragile if the provider rotates) |
| A6 | `max_tokens` must be ≤16384 for some OpenAI-compatible models | §7 | Requests fail 400 `max_tokens is too large` |
| A7 | The `guard` package enforces target scope | §5 | **FALSE for the pinned build — confirmed 2026-11-08.** `guard/guard.go`: *"The RoE authorization-scope mechanism was removed; a replacement may be added later."* The egress allowlist is the *only* scope enforcement; there is none at the app layer. |

### What changed in the 2026-11-20 upstream merge

The fork moved from `a908e1e` (v0.5.1) to `ab40834` (487 commits, post-v0.6.0). Four changes
matter to an operator:

- **Secrets are encrypted at rest.** `ARTEX_SECRET_KEY` (or `keys/secret.key`) is now required.
  Startup **refuses** when encrypted rows exist and the key is missing, and losing the key
  loses the stored credentials. `artex_keys` is a named volume in the compose file; put it in
  the same backup as `db_data`.
- **The untrusted-output boundary is on by default.** `docker-compose.hardened.yml` pins it to
  `1`; `preflight.sh` fails if it is disabled. Expect ~154 bytes per tool result.
- **The first-run token is not an env var.** It is generated at startup and printed to the log.
  `preflight.sh` no longer checks for `ARTEX_SETUP_TOKEN` (which ARTEX never read).
- **Data and keys moved to named volumes** `artex_data:/app/data` and `artex_keys:/app/keys`.
  The previous `ARTEX_STATE_DIR=/opt/artex/state` mount was inert — the binary never read it.

New opt-in egress paths (all denied by the allowlist unless you add them): `api.keenable.ai`
(web search), S3 endpoints (cold-task archives), `api.github.com` (update banner, pinned off).

---

## 4. Run

### Phase 0 — build (egress open, on a different host or a short window)

```bash
cp .env.hardened.example .env.hardened
chmod 600 .env.hardened
$EDITOR .env.hardened

./scripts/pin-digests.sh                 # prints digest-pinned refs; paste into .env.hardened
COMMIT=<full-40-char-sha> ./scripts/verify-build.sh
```

`verify-build.sh` clones at `COMMIT`, records author/date/signature status, hashes the tree,
builds with `--no-cache`, and writes `artifacts/build-attestation.txt`. It refuses to build from
a branch tip — only an explicit commit.

Do not skip the audit in §6 because the build "worked."

### Phase 1 — lock egress

```bash
cp nftables/scope.allow.example nftables/scope.allow
cp nftables/resolvers.allow.example nftables/resolvers.allow
$EDITOR nftables/scope.allow nftables/resolvers.allow

sudo ./scripts/egress-apply.sh           # proxy mode (default)
# or: sudo ./scripts/egress-apply.sh --direct   # pinned LLM IPs, no relay
```

For more than one engagement, use a profile instead of editing the top-level files:

```bash
cp -r nftables/profiles/_template nftables/profiles/<engagement>
$EDITOR nftables/profiles/<engagement>/scope.allow
sudo ./scripts/egress-apply.sh --profile <engagement>
./scripts/render-squid-scope.sh --profile <engagement>
sudo ./scripts/egress-apply.sh --revert   # between engagements: back to default deny
```

There is no "general" profile on purpose. Profiles make the tooling reusable; they do not
make the allowlist broad. See `nftables/profiles/README.md` for why a provider-wide set
removes the authorization control instead of widening it.

If you are the operator and the engagement has no client-imposed network boundary, open
mode is the honest posture: full public egress, no per-target lists, application scope only.
It still closes metadata/link-local, RFC1918 outside the lab, and lab→host services, and it
logs every drop.

```bash
sudo ./scripts/egress-apply.sh --open     # scope layer off, baseline on, relay transparent
sudo ./scripts/egress-apply.sh --revert   # everything off
```

`--open` flips both gates: the kernel table `inet artex` is removed, and the relay loses its
domain ACL (`http_access allow all` before `deny all`), because the app's `global_proxy`
sends *target* traffic through squid, not just model calls. The relay stays bound to the
bridge gateway, so it remains a log, not an open proxy. A scoped apply puts the ACL back.

Everything reachable in open mode is the agent's choice, not the kernel's. Confirm the app's
own scope guard refuses an out-of-scope target before the first packet — see README §3 A7.

Verify before trusting it:

```bash
curl -sS --max-time 5 https://example.com    # must fail
curl -sS --max-time 4 http://169.254.169.254/ # must fail
nft list table inet artex | head -60
```

### Phase 2 — start

```bash
./scripts/preflight.sh --scope-host 10.0.0.5
docker compose --env-file .env.hardened -f docker-compose.hardened.yml up -d
docker compose -f docker-compose.hardened.yml logs -f artex | grep -F '[auth]'
```

Then reach the UI **only** over a tunnel:

```bash
ssh -N -L 8787:127.0.0.1:8787 ops@vps
```

First boot: while no admin password is stored, ARTEX generates a one-time setup token and
prints it to its log. Claim the instance with it:

```bash
docker compose -f docker-compose.hardened.yml logs artex | grep -F 'Setup token'
```

The token is cleared once a password is stored. There is no env var for it; the control that
keeps a first visitor from claiming the instance is the loopback-only publish above.

### Phase 3 — engage

- Start long runs **after 11:00 local (CET)** or on a weekend: DeepSeek peak is 01:00–04:00 and
  06:00–10:00 UTC Mon–Fri. Off-peak is exactly half price.
- `preflight.sh` checks `timedatectl` sync — off-peak billing depends on your clock being right.
- **State the scanner policy in the task goal.** `prompts/scanner-policy.md` has a paste-ready block.
  Without it the model reads "no fuzzing" as "no scanners" and hand-rolls `curl` instead of running
  `nuclei`/`bbot` (2026-11-08 engagement runs: 917 Bash commands, zero scanner invocations).
- Watch the dashboard's token-spend panel; if it diverges from your estimate by >2×, a model is
  looping on malformed tool calls. Kill it, don't wait.

### Phase 4 — teardown

```bash
./scripts/teardown.sh --confirm
```

Then walk the printed checklist: provider snapshots, block-storage backups, DNS records,
the LLM provider's request logs (retention is set by *them*, not you), and the scope document.

---

## 5. What actually enforces scope

Two independent things, and you want both:

1. **`nftables/scope.allow`** — kernel-level, unbypassable from inside the container. This is the
   real boundary. It holds only if the list is correct and complete.
2. **ARTEX's `guard` package** — **not a scope control in this build.** `guard/guard.go` says the
   RoE authorization-scope mechanism was removed. What remains is an audit log plus 20 built-in
   intercept rules for destructive commands (`rm -rf`, `mkfs`, `DROP TABLE`, DELETE endpoints).
   None reference target scope. With the kernel layer off, scope is prompt-only.

Do not use (2) as evidence that (1) is unnecessary. Before the first engagement, run one
deliberate out-of-scope probe from inside the container and confirm it fails:

```bash
docker compose -f docker-compose.hardened.yml exec artex \
  sh -c 'curl -sS --max-time 5 -o /dev/null -w "%{http_code}\n" http://198.51.100.7/ || echo BLOCKED'
```

`198.51.100.7` is TEST-NET-2, guaranteed not to be in your scope. If that returns anything but
`BLOCKED`, stop and fix the ruleset.

---

## 6. Audit checklist for the fork (do this before you sign anything)

The value you're claiming is "trust this build." That claim is only as good as this list.
Status recorded 2026-11-14 against the deployed build; evidence in `SECURITY-REVIEW.md`.

- [x] `git log --format='%H %G? %an %ci'` — 11 local commits, all build/UI, all authored by the
      operator. All signed with an SSH signing key and **verified** by GitHub (`G? = G`).
- [ ] Diff against upstream if you have any copy: `git diff --stat upstream/main..HEAD`. Expect
      it confined to `web/` i18n, `agent/prompt.go`, README/docs, and `.env.example`.
      **Could not run — upstream unreachable.** The fork is the only baseline.
- [x] `selfupdate/` — does it phone anywhere? Is it reachable at all with egress locked?
      **The package does not exist.** `update.sh` is interactive and rebuilds; not called at runtime.
- [x] `server/` auth: setup-token comparison, rate limiting, session signing, CORS default.
      Constant-time token compare (`auth.go:255`), per-IP login limiter (`login_limit.go`),
      JWT key 0600 in its own volume. **CORS is `*`** — see `SECURITY-REVIEW.md` F3.
- [x] `mcphttp/` and `intercept/` — outbound hosts, SSRF surface, request logging of secrets.
      `mcphttp` URLs are operator-supplied and **lack the internal-address guard `notify` has** (F2).
      `intercept/` does not log `Authorization`/`Cookie`. `enrich/` takes a config URL.
- [x] `notify/` — webhook destinations; anything not yours is an exfil channel.
      Destination comes from `notification_channels.config`; the dialer blocks internal
      addresses; no channel is enabled by default. The four IM adapters are opt-in.
- [x] `Dockerfile`, `install.sh`, `update.sh`, `start-cloud.sh` — `curl | sh`, unpinned bases,
      `ADD` from URL. Bases are digest-pinned, every download is SHA-256-verified,
      `pip --require-hashes`, `npm ci --ignore-scripts`, no `curl | sh`, no `ADD <url>`.
- [x] `go.mod` — dependencies pointing at forks/pseudo-versions instead of tagged releases.
      One `replace`: `Autumn-27/norma => BaaRai/Norma v0.4.4`, **byte-identical to upstream
      v0.4.4** (F5). The `v0.0.0-yyyymmdd` entries are indirect and normal.
- [ ] Image provenance: build from source yourself, then compare behaviour with the published
      GHCR image in an isolated netns. **Not done** — the deployed image was built from this
      checkout; the published `ghcr.io` image was never pulled or compared.

If any of these can't be answered because upstream is unreachable, say so plainly in whatever
you publish. "I could not verify X" is a defensible sentence; silence is not.

---

## 7. Model configuration

`.env.hardened` carries the endpoint; profiles live in the UI (`System → LLM settings`).

```
ARTEX_LLM_PROVIDER=openai
ARTEX_LLM_MODEL=deepseek-flash
ARTEX_LLM_BASE_URL=https://api.deepseek.com/v1
ARTEX_LLM_PROXY=http://172.28.0.1:3128
```

- **`max_tokens`: set it explicitly per profile.** DeepSeek Flash allows 384K output, so 32768 is
  safe there; other OpenAI-compatible endpoints reject >16384 with `400 max_tokens is too large`.
- **Thinking mode is on by default** and reasoning tokens bill as output. A tight budget gets
  eaten by the reasoning channel and you get an empty assistant message. If you see empty
  replies, raise `max_tokens`, don't lower it.
- **Failover chain** (`llmpool`) is priority-ordered, not per-role: the active profile heads the
  chain, then priority DESC, skipping members whose context window can't hold the request. Put
  your cheap model active and an expensive one behind it only for hard failures — the chain does
  not route by difficulty.
- **Cache is the bill.** 80–90% of an engagement's tokens are cache reads. DeepSeek off-peak
  charges $0.003/M for those; a gateway charging $0.15/M is 50× on the dominant line item.
  Measure, don't assume: `tools/model-ab.py`.

Run the harness before committing to a model for the real engagement:

```bash
export AB_API_KEY=<key for the endpoints you are testing>
python3 tools/model-ab.py \
  --endpoint https://api.deepseek.com/v1 --model deepseek-flash --label ds-flash \
  --endpoint https://api.orcarouter.ai/v1 --model orca/orcacyber-flash-1.0 --label orca-flash \
  --price ds-flash=0.15/0.60 --price orca-flash=0.80/1.60 \
  --out artifacts/ab.csv

# cheaper first pass: the free abliterated tier costs nothing to measure
# --endpoint https://api.orcarouter.ai/v1 --model orca/orcacyber-flash-1.0-free --label orca-free
```

It reports, per model: refusal rate, malformed tool-call rate, tokens per completed turn, and
cost per completed turn at published prices. A model with a 5% invalid-JSON rate burns ~3× the
tokens looping — that beats any headline price difference.

---

## 8. Off-peak reference (DeepSeek)

| | UTC | CET (winter) |
|---|---|---|
| Peak | 01:00–04:00, 06:00–10:00 Mon–Fri | 02:00–05:00, 07:00–11:00 |
| Off-peak (50% off) | everything else + weekends + CN holidays | from 11:00 onward |

A run started at 10:00 CET crosses into cheap pricing ~20 minutes in. Weekend runs are fully
off-peak.

---

## 9. Things that will bite you

- **`docker compose down` without `-v` keeps the database** — including credentials, loot, and
  the target graph. `teardown.sh` uses `-v` and then verifies the volume is gone.
- **The traffic-recording proxy on 8788 records everything**, including cookies and tokens.
  It is not published; if you need it, tunnel to it explicitly and treat the resulting pcaps as
  client-confidential material.
- **Cloud-init and provider agents run outside your bridge.** The egress ruleset only governs
  `172.28.0.0/24`. Harden the host separately (no docker group for unprivileged users, key-only
  SSH, no other listeners).
- **DNS is an exfil channel.** `resolvers.allow` should be one resolver you control or a
  well-known one, and you should be able to read its query log afterwards.
- **`ARTEX_CORS_ORIGINS` empty is correct** for same-origin UI. Populating it widens the API.
