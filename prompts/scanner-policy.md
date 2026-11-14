# Scanner policy — task-goal block

Paste the block below into the `goal` field of a task (and any hint/steer text). It exists
because the model reads "no fuzzing, no brute force" as "no scanners", which is how the
2026-11-08 engagement runs ended up doing 917 Bash commands of hand-rolled `curl` while
`nuclei`, `bbot`, `subfinder`, `katana` and `httpx` sat unused in `/usr/local/bin`.

Two facts behind the wording:

1. `nuclei` tags are not one axis. `tech`/`misconfig`/`exposure`/`ssl` are read-only GETs on
   the same surface a browser uses; `fuzz`, `dast`, `intrusive` send payloads. A blanket ban
   on "fuzzing" must not be read as a ban on the first group.
2. `bbot` Mode P never contacts the target (`-s seed` only). It is the correct choice when a
   program bans scanning — and it is the only way the passive layer (CT, wayback, urlscan,
   InternetDB) gets covered at all.

---

## The block

```text
Scanner policy (explicit — do not infer it from "no DoS"):

PERMITTED by default, within the rate bounds below:
- Passive, zero-touch: bbot Mode P (-s seed, no -t), or subfinder/httpx against
  OSINT output. Nothing is sent to the target.
- Active-safe: bbot Mode A; httpx fingerprinting; katana crawl with
  spider_depth<=2; ffuf content discovery; nmap -sT with a bounded port list;
  nuclei templates limited to tags tech,misconfig,exposure,ssl,headers,cname,takeover.
- ALWAYS add to nuclei: -etags dast,fuzz,intrusive,dos.

NOT PERMITTED without a separate, written authorisation for this task:
- nuclei -dast, -tags fuzz|intrusive|dos, or any template that submits payloads;
- sqlmap, dalfox, wpscan --passwords, ffuf with injection payload lists;
- bbot loud families: paramminer_*, virtualhost, waf_bypass, bypass403, dnsbrute,
  portscan, host_header, generic_ssrf, lightfuzz.

Rate bounds: -rl 50 -c 10 for nuclei, ffuf -rate 50 -t 15, nmap --max-rate 30.
One burst of at most 20 requests to establish a rate limit, stop at the first 429.
No sustained load. No port scan wider than the task's stated port list.

Evidence: save the exact command and the tool's native output (nuclei -j -o, bbot
-om json, ffuf -of json) under /app/data/tasks/<id>/. A scanner hit is a lead, not a
finding: confirm it by hand before report_finding.

Tooling: nuclei, bbot, subfinder, httpx, katana, ffuf, dalfox, sqlmap, wpscan and
playwright are preinstalled. Check `command -v <tool>` before concluding a tool is
missing. If a tool is absent or blocked by egress, call ask_operator with the exact
command to run — do not silently substitute a hand-rolled loop.
```

---

## What "complete" means for the recon phase

Use this as the acceptance list for an external recon task. It is deliberately tool-shaped,
because "enumerate the attack surface" is not checkable and this is.

| Layer | Minimum evidence |
|---|---|
| Passive | `bbot -s <root> -m crt,certspotter,urlscan,wayback,shodan_idb,ipneighbor,asn` output, or an explicit note that egress to those providers is blocked |
| DNS | resolved set + wildcard test (`<random>.<root>`), and whether `*.<sub>` is a wildcard |
| Ports | `nmap -sT` over a named port list **with `-sV`**, per IP |
| HTTP | `httpx` over the discovered names: status, title, tech, TLS, CDN/WAF tag |
| Paths | `ffuf` per vhost, with the wordlist source named |
| Templates | `nuclei` safe tag set, JSONL kept |
| Web surface | `katana` on any HTML app (not on a JSON-RPC endpoint) |
| Negative controls | one out-of-scope host attempted and blocked, recorded |

A run that skips a row without saying why is incomplete, not "clean".
