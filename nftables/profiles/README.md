# Engagement profiles

One directory per assignment. A profile is the **only** thing that differs between
engagements: the ruleset, the relay config, and the scripts stay identical.

```
nftables/profiles/
  _template/          copy this, never apply it
    scope.allow       in-scope CIDRs (kernel + squid IP literals)
    edge.allow        shared CDN prefixes (relay-only)
    llm.allow         pinned provider IPs (--direct mode only)
    resolvers.allow   DNS resolvers the lab may query
  acme-2026-11/       a real assignment, populated from its signed scope doc
```

## Why profiles instead of a wider allowlist

The request "open it generally so we can take any assignment" has two readings, and
only one of them is safe:

| Reading | What it means | Verdict |
|---|---|---|
| **Reusable** | Any assignment can be loaded with one command; each is closed before and after its window | Yes. That is this directory. |
| **Broad** | A standing allowlist that covers "anywhere a future target might be" | No. That is not a wider scope, it is the absence of scope. |

A standing broad set fails in three ways at once:

1. **It deletes the authorization control.** The kernel allowlist is the only thing in
   this stack that knows what you were authorised to touch. `in_scope` = "the internet"
   means the answer to "what was I allowed to reach?" is "everything", and the scope
   document becomes decorative.
2. **It widens the prompt-injection blast radius.** The model reads target-controlled
   content. Every address in `in_scope` is a place a manipulated agent can be told to
   go. Provider-wide ranges hand that decision to whoever wrote the page the agent
   fetched last.
3. **It is shared infrastructure.** Vultr/DO/GCP prefixes are other tenants. "The client
   is hosted there" is not attribution, and the rule in `prompts/scope-review.md` is
   §C: never widen on a shared edge.

Generality belongs in the **name layer**, not the address layer. Squid's `scope_domains`
already reaches any name under the client's zones regardless of the IP it resolves to.
For a new assignment you add their zone names there and a handful of `/32`s for tools
that ignore `HTTP_PROXY`. You do not add an ASN.

## Workflow

```bash
# start an assignment
cp -r nftables/profiles/_template nftables/profiles/acme-2026-11
$EDITOR nftables/profiles/acme-2026-11/scope.allow
sudo ./scripts/egress-apply.sh --profile acme-2026-11
./scripts/render-squid-scope.sh --profile acme-2026-11

# widen by one host, with evidence and a blast-radius number
sudo ./scripts/scope-add.sh --profile acme-2026-11 203.0.113.10/32 \
  --evidence "prod web, cert SAN matches acme.com, RDAP netblock is client-owned"

# switch or close
sudo ./scripts/egress-apply.sh --revert        # between engagements: default deny
```

`scope-add.sh` refuses provider-wide additions without an explicit `--allow-large`, and
prints the address delta every time. If the honest answer is "nothing should be added",
it says so and stops.

## Rules for a profile

- `/32` by default. `/24` is the ceiling for a shared-ASN host, and only with attribution.
- A larger prefix is acceptable only for a **client-owned** netblock proven by RDAP, and
  it must carry its evidence on the same line.
- Names go in `proxy/squid.conf` `scope_domains`; prefixes go in `scope.allow`. A bare IP
  that resolves to the client's CDN is a name problem, not a scope problem.
- `_template` is never applied. `egress-apply.sh` will happily refuse an empty profile,
  which is the correct failure.
