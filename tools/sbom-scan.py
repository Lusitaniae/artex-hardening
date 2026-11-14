#!/usr/bin/env python3
"""SBOM + CVE pass over the deployed ARTEX build, using the OSV database.

Inputs:
  go.mod / go.sum          -> Go module graph
  requirements-bbot.lock   -> PyPI (bbot venv, hash-pinned)
  dpkg-query -W in image   -> Debian bookworm packages

Queries https://api.osv.dev/v1/querybatch, then fetches details for hits.

Usage:
  ARTEX_HOST=root@your-vps ./tools/sbom-scan.py [image:tag]

Caveat that matters: OSV's Debian data records security-tracker entries, and an entry
with `introduced: 0` and no `fixed` event (the common no-DSA case) is reported as
affecting every version. Treat the Debian rows as "tracker entries touching this
package", not "exploitable CVEs". See SECURITY-REVIEW.md §9.
"""
import json, os, re, subprocess, sys, urllib.request

OSV = "https://api.osv.dev/v1"
BATCH = 900


def post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def go_modules(path="go.mod"):
    mods, inside = [], False
    for line in open(path):
        line = line.strip()
        if line.startswith("require ("):
            inside = True; continue
        if inside and line == ")":
            inside = False; continue
        if line.startswith("replace") or "=>" in line:
            continue
        m = re.match(r"^([\w.\-/]+)\s+(v[\w.\-+]+)", line)
        if m and (inside or line.startswith("require")):
            mods.append((m.group(1), m.group(2)))
    return [m for m in mods if not m[0].startswith("github.com/Autumn-27/artex")]


def pypi_packages(path="requirements-bbot.lock"):
    out = []
    for line in open(path):
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s\\]+)", line.strip())
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def debian_packages(image, host):
    raw = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", host,
         f"docker run --rm --entrypoint dpkg-query {image} -W"],
        capture_output=True, text=True, check=True).stdout
    out = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].strip():
            out.append((parts[0].strip(), parts[1].strip()))
    return out


def query(queries):
    results = []
    for i in range(0, len(queries), BATCH):
        chunk = queries[i:i + BATCH]
        r = post(f"{OSV}/querybatch", {"queries": chunk})
        results.extend(r.get("results", []))
    return results


def main():
    host = os.environ.get("ARTEX_HOST", "root@<deploy-host>")
    image = sys.argv[1] if len(sys.argv) > 1 else "artex:local-20261109"
    groups = {
        "Go": [(n, v, {"name": n, "ecosystem": "Go"}) for n, v in go_modules()],
        "PyPI": [(n, v, {"name": n, "ecosystem": "PyPI"}) for n, v in pypi_packages()],
        "Debian:12": [(n, v, {"name": n, "ecosystem": "Debian:12"}) for n, v in debian_packages(image, host)],
    }
    allq, keys = [], []
    for eco, items in groups.items():
        for name, ver, pkg in items:
            allq.append({"package": pkg, "version": ver})
            keys.append((eco, name, ver))
    print(f"queried {len(allq)} packages "
          f"({len(groups['Go'])} go, {len(groups['PyPI'])} pypi, {len(groups['Debian:12'])} debian)",
          file=sys.stderr)
    res = query(allq)
    hits = []
    for (eco, name, ver), r in zip(keys, res):
        ids = [v["id"] for v in r.get("vulns", [])]
        if ids:
            hits.append((eco, name, ver, ids))
    print(f"packages with advisories: {len(hits)}", file=sys.stderr)

    unique = sorted({i for _, _, _, ids in hits for i in ids})
    details = {}
    for i in range(0, len(unique), 100):
        for vid in unique[i:i + 100]:
            try:
                with urllib.request.urlopen(f"{OSV}/vulns/{vid}", timeout=60) as r:
                    details[vid] = json.load(r)
            except Exception as e:
                details[vid] = {"summary": f"(fetch failed: {e})", "severity": []}

    def sev(d):
        for s in d.get("severity", []):
            if s.get("type") == "CVSS_V3":
                return s.get("score", "").split("/")[0]
        return ""

    print("\n| ecosystem | package | version | advisory | severity | summary |")
    print("|---|---|---|---|---|---|")
    for eco, name, ver, ids in sorted(hits):
        for vid in ids:
            d = details.get(vid, {})
            s = sev(d).replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
            summ = (d.get("summary") or d.get("details", "")[:80]).replace("|", "/").strip()
            print(f"| {eco} | `{name}` | {ver} | [{vid}](https://osv.dev/vulnerability/{vid}) | {s} | {summ[:90]} |")


if __name__ == "__main__":
    main()
