# VM setup for running an untrusted ARTEX build

Answers the setup question only. Code audit lives in `../STATUS.md`, runtime
containment lives in `../README.md` (compose + nftables). This folder is the
hypervisor layer underneath both.

---

## 1. The decisions

| Question | Answer | Why |
|---|---|---|
| Fedora Silverblue? | **No. Ubuntu Server cloud image.** | Immutability is a *host integrity* feature. Here the whole VM is disposable, so it buys nothing. It costs you rpm-ostree friction every time you want Docker, and a second distro to reason about. |
| Chrome with JS disabled? | **No. Firefox, JS on.** | The UI is a Next.js/React static export. With JS off you get an empty shell — you'd be testing nothing. And JS isn't the threat model: the VM boundary is. |
| One VM or two? | **Two.** | A browser inside the app VM is not a safety layer — a browser exploit then lands next to the Docker socket and the database. The browser must not share a kernel with the app. |
| Ubuntu or Debian? | **Ubuntu 26.04**, matching the DigitalOcean image. | Three identical guests (local app, local browser, droplet) means one set of commands and one set of surprises. |
| Docker on the host? | **No.** Docker only inside the app VM. | Root daemon on the machine you actually care about is the single biggest own-goal available here. |
| Browser VM local or a second droplet? | **Local, headful.** | One provider compromise then cannot take both halves. But the decisive reason is the VPC — see §3. |

One thing that is *not* a decision: **do not X11-forward the browser to your
host.** X11 has no client isolation — any X client can read the keyboard and
screen. That turns an untrusted browser into a host keylogger. Use the SPICE
console (`virt-viewer`) so the display stays inside the guest. This script
deliberately does not install `spice-vdagent`, which also removes the
clipboard/drag-and-drop channel.

---

## 2. Topology

```
        your host (KVM guest, nested virt on)
        ├── artex-browser   Ubuntu Desktop, Firefox as user `web`
        │     └── ssh -N -L 127.0.0.1:8787  (restricted key, run as `ops`)
        │             │
        │             └──────────────┐
        └── artex-app  Ubuntu Server │  docker: artex + postgres
              172.28.0.0/24 bridge   ←┘  127.0.0.1:8787 only
                    │
                    └── nftables default-deny egress (../nftables/)

        DigitalOcean (real engagement only)
        └── artex-run   same image, loaded over SSH, locked from first boot
                └── same restricted tunnel from the local browser VM
```

The browser VM has no direct route to the app. It only sees `127.0.0.1:8787`
inside itself. That is the whole point: nothing the UI can do in the browser
gives it a network position.

---

## 3. Where the browser lives

Your app is already on a droplet, so the question is: headful VM on your desk,
or a second droplet with some remote-desktop protocol?

**Local headful. It is both safer and faster.** Four reasons, in order of weight:

1. **A second droplet puts both halves in one VPC.** Two droplets in the same
   DigitalOcean VPC can reach each other on the private network by default.
   That is a lateral movement path from a compromised app to your browser
   session that does not exist in the local design, where the only route is a
   forward-only SSH tunnel you initiated. You can fix it with separate VPCs, but
   it is a footgun you don't have to own.
2. **No remote-display protocol to babysit.** Headful-in-the-cloud means VNC,
   xrdp or X2Go, shipping untrusted framebuffer and input events into a client
   on your real machine. A local VM gives you SPICE on `127.0.0.1` — the display
   never crosses a network.
3. **One provider compromise takes one half, not both.** If your DO account is
   drained, your browser, its session, and anything you typed into it stay
   local. Both-in-DO means one leaked token or one support action owns
   everything.
4. **Latency.** A local browser talking to a remote API over `ssh -L` is
   snappy — only the UI's HTTP goes over the wire. Remote desktop ships screen
   updates instead, which is exactly the wrong thing to put on a link you're
   also using to watch a scan.

There is also no IP-hiding argument for a cloud browser: the app already runs in
DO, so **your home IP never appears in engagement traffic either way**. The only
packets leaving your house are SSH to `droplet:22`.

Cost of the wrong choice: a second `s-2vcpu-4gb` (~$24/mo) plus desktop
packages, for a slower and less isolated setup.

The one thing you do need from DO: the droplet's public IP, so the browser VM's
egress can be pinned to exactly that host on port 22. Without `TUNNEL_HOST` the
browser VM will happily reach the whole internet — which is the thing a
compromised browser most wants.

---

## 4. Local VMs

Your app runs on a droplet, so you need **only the browser VM**:

```bash
chmod +x vm/lab-vms.sh
sudo usermod -aG libvirt,kvm "$USER"   # then log out / back in

TUNNEL_HOST=<droplet-public-ip> ./vm/lab-vms.sh create-browser
```

| VM | Spec | Role |
|---|---|---|
| `artex-browser` | 2 vCPU / 4G / 18G | Firefox only, egress pinned to `<droplet>:22` |
| `artex-app` (optional) | 4 vCPU / 8G / 24G | `create-app` — offline dry runs and canaries only |

`create` builds both, which is what you want if you're testing a build before
spending on the droplet. `create-browser` on its own is the everyday case.

Sizing assumes this host (8 vCPU, 23G, 75G free). Browser-only is ~18G, so you
have room; both is ~50G. If a build starts swapping the host, drop `APP_MEM` to
6144 — a Go compile plus the Next.js build is the peak, not the run.

`./vm/lab-vms.sh destroy` removes the VMs and their disks; the base cloud image
stays cached for a fast rebuild. Treat them as cattle: rebuild rather than
repair.

Verify the pin actually took, from the host, before you trust it:

```bash
./vm/lab-vms.sh pin-egress --show
# and prove the negative, from inside the VM:
ssh ops@<browser-vm-ip> -i ~/.ssh/artex_lab_ed25519 \
  'curl -sS --max-time 5 https://example.com || echo BLOCKED'
```

If that second one doesn't say `BLOCKED`, the browser VM is on the open
internet and the isolation is decorative.

**Repinning without a rebuild.** DO droplet IPs change whenever you rebuild the
droplet, and rebuilding an 18G VM to change one address is silly:

```bash
./vm/lab-vms.sh pin-egress 203.0.113.45   # new droplet IP
./vm/lab-vms.sh pin-egress --show         # confirm
./vm/lab-vms.sh pin-egress --open         # drop the pin (e.g. to apt install)
```

`--open` is deliberately explicit and warns on use: it leaves the browser VM on
the open internet, which is the state you never want while a hostile UI is on
screen. Re-pin before you browse. The apply is atomic (`nft -f`), and the SSH
session doing the applying survives it because its replies match
`ct state established,related` — you cannot lock yourself out by repinning.

One more thing `pin-egress` is not for: it does not stop the browser from
talking to the app. That is the tunnel's job, and loopback is always allowed.

---

## 5. Browser VM hardening (the part that actually matters)

The VM is the boundary. These are the cheap wins inside it:

The script seeds this for you: an `artex` profile, a GDM autologin for `web`,
and an autostart entry that opens `http://127.0.0.1:8787/`. To do it by hand
afterwards (the display is the SPICE console, so run it from a terminal in that
session, not over SSH):

```bash
# as `ops`, then hand the desktop session to `web`
sudo -u web firefox --CreateProfile artex
sudo -u web firefox -P artex --no-remote
```

**Snap Firefox does not read `~/.mozilla`.** Its `HOME` is
`~/snap/firefox/common`, so the profile that actually loads is
`/home/web/snap/firefox/common/.mozilla/firefox/artex`. Put `user.js` there or
your prefs silently do nothing (`-P artex` will happily create an empty profile
at the snap path).

In that profile:

- **No extensions.** An extension is third-party code with full page access.
- **No password manager, no autofill, no sync, no account.** `about:config` →
  `signon.rememberSignons=false`, `browser.formfill.enable=false`,
  `identity.fxaccounts.enabled=false`.
- **Nothing else in this browser, ever.** Not your email, not your GitHub. One
  profile, one origin, one purpose.
- **No clipboard agent.** Not automatic: `ubuntu-desktop-minimal` pulls
  `spice-vdagent` in as a dependency, so the script purges it in `runcmd` and
  strips the `spicevmc` channel and both `redirdev` USB-redirection devices
  from the domain XML. Verify with `dpkg -l spice-vdagent` (nothing) and
  `virsh dumpxml --inactive artex-browser | grep spicevmc` (nothing).

If you want the browser to be able to read nothing but the tunnel, that is
already the case: it runs as `web`, the SSH key lives in `/home/ops/.ssh`.

---

## 6. The tunnel

Run this as `ops` in the browser VM, not as `web`:

```bash
ssh -N -L 127.0.0.1:8787:127.0.0.1:8787 tunnel@<app-ip> -i ~/.ssh/artex_tunnel_ed25519
```

`<app-ip>` is the droplet's public IP when the app is in DO. The local app VM
gets the restricted key from cloud-init; **on the droplet you install it
yourself** once:

```bash
# on the droplet
sudo useradd -m -s /bin/bash tunnel && sudo passwd -l tunnel
sudo install -d -m 0700 -o tunnel -g tunnel /home/tunnel/.ssh
printf '%s\n' 'restrict,port-forwarding,permitopen="127.0.0.1:8787",command="/bin/false" ssh-ed25519 AAAA...' \
  | sudo tee /home/tunnel/.ssh/authorized_keys
sudo chown tunnel:tunnel /home/tunnel/.ssh/authorized_keys && sudo chmod 600 /home/tunnel/.ssh/authorized_keys
```

The key is restricted server-side to exactly that one forward:

```
restrict,port-forwarding,permitopen="127.0.0.1:8787",command="/bin/false" ssh-ed25519 AAAA...
```

So if the browser VM is compromised and the key is stolen, the worst case is
"can open a port forward to the app's own loopback." No shell, no second
destination, no agent forwarding.

Then browse to `http://127.0.0.1:8787`. Never `http://<vm-ip>:8787` — if that
works, something is published that shouldn't be.

### If the hypervisor host is headless

`virt-viewer --domain-name artex-browser` needs a display on the host, and a
headless box has none. Forward **SPICE**, not X11: the framebuffer stays in the
guest, the client runs on your desktop, and the display port never leaves the
SSH tunnel.

SPICE listens on the host's loopback with `disable-ticketing=on` — no password.
The tunnel is the authentication, so do not expose 5900.

```bash
# on the desktop
ssh -N -L 15900:127.0.0.1:5900 pedro@dev.tail6e1687.ts.net
# then, in another terminal on the desktop
virt-viewer --connect spice://127.0.0.1:15900
```

Use a high local port (`15900`): `5900` is where your own local VMs listen.
`remote-viewer` and `spicy` accept the same URI. macOS/Windows builds ship with
virt-manager; on Debian/Ubuntu it is `apt install virt-viewer`.

If virt-viewer says **"Unable to connect to libvirt with URI"**, it was given
`--domain-name` or a `qemu://` URI — so it is looking for libvirt on your
desktop (`qemu:///system` means *your* machine) instead of at the display
endpoint. Two things work:

```bash
# A. direct display URI: no libvirt involved at all
virt-viewer --connect spice://127.0.0.1:15900     # or: remote-viewer spice://127.0.0.1:15900

# B. one command, libvirt over SSH, console tunnelled by libvirt itself
#    (no separate -L needed; `pedro` must be in the libvirt group on the host)
virt-viewer --connect 'qemu+ssh://pedro@dev.tail6e1687.ts.net/system' \
            --domain-name artex-browser
```

Do not use `qemu+ssh://root@<droplet-ip>/system`: the droplet has no libvirt and
no such domain. Check the tunnel before blaming the client:
`nc -z 127.0.0.1 15900 && echo tunnel ok`.

Do **not** fall back to `ssh -X` and run virt-viewer on the host: the X11
forwarding protocol lets the far end read your desktop's other windows and
keystrokes. That is the same reason §1 says not to X11-forward the browser.

---

## 7. DigitalOcean

Local first, droplet second. Do not pay hourly to discover that the build is
broken. Region: `fra1` or `ams3` — put the region in the report, the provider
sees target data.

```bash
# dedicated key, dedicated VPC, no other droplets in it
doctl compute ssh-key import artex-do --public-key-file ~/.ssh/artex_lab_ed25519.pub
doctl compute vpc create artex-vpc --region fra1 --ip-range 10.116.0.0/20
doctl compute droplet create artex-run \
  --image ubuntu-26-04-x64 --size s-4vcpu-8gb-amd --region fra1 \
  --vpc-uuid <vpc-uuid> --ssh-keys <key-id> --tag-name artex --wait

# inbound: your IP only, on 22. Nothing else. 8787 is never public.
doctl compute firewall create --name artex-fw --droplet-ids <droplet-id> \
  --inbound-rules "protocol:tcp,ports:22,address:$(curl -s ifconfig.me)/32" \
  --outbound-rules "protocol:tcp,ports:all,address:0.0.0.0/0" \
                         "protocol:udp,ports:all,address:0.0.0.0/0"
```

Then, on the droplet:

- Leave `--enable-monitoring` off (default). One fewer agent outside your bridge.
- Put **no DigitalOcean API token** on the box. If the build can read a token,
  the build can rent you more boxes.
- Block metadata at the host level, not only in the docker ruleset:
  ```bash
  nft add table inet artex_meta
  nft 'add chain inet artex_meta out { type filter hook output priority -10; policy accept; }'
  nft add rule inet artex_meta out ip daddr 169.254.169.254 drop
  ```
- Ship the image in, don't build on the droplet:
  ```bash
  # local app VM
  docker save artex:local | zstd -3 | ssh ops@<droplet> 'zstd -d | docker load'
  ```
  This keeps the droplet's egress closed from the first boot; only `apt install
  docker.io` needs a short, watched window.
- Same restricted tunnel from the browser VM, same `permitopen`.

Cost reference: `s-4vcpu-8gb-amd` is ~$0.0714/hr. A few hours per engagement is
pocket change; the droplet you forget about for a month is not.

---

## 8. Order of operations

1. `TUNNEL_HOST=<droplet-ip> ./vm/lab-vms.sh create-browser`
   (add `create-app` too if you want to canary the build before paying for DO)
2. Clone at the pinned commit, build, attest (`../scripts/`) — in the local app
   VM, or on the droplet during a short watched egress window.
3. **Canary run — before any real target.** Apply `../nftables/artex-egress.nft`
   with empty allow-sets, start the stack, and watch it fail:
   ```bash
   sudo conntrack -E -o timestamp | grep -v '127.0.0.1'
   sudo tcpdump -ni any -vv 'not port 22 and not port 53' -w /tmp/canary.pcap
   ```
   Everything it *tries* to reach is the finding. A default-deny tells you it
   was blocked; the pcap tells you what it wanted.
4. Second pass with egress **allowed but logged** through the squid relay — a
   beacon you can see is worth more than a beacon you merely stopped.
5. Only then the droplet, and only then a real scope.

---

## 9. Teardown

```bash
./vm/lab-vms.sh destroy
doctl compute droplet delete <droplet-id>
doctl compute vpc delete <vpc-uuid>
doctl compute ssh-key delete <key-id>
```

Provider snapshots and backups are residue you cannot `rm`. Check the DO
dashboard, not just the CLI.

---

## 10. What this does and does not buy

**Buys:** kernel-level separation between the browser and the app, no Docker
socket on your real machine, no X11 path from untrusted code to your keyboard,
a tunnel credential that is useless outside one port, and a disposable guest you
rebuild instead of cleaning.

**Does not buy:** safety from a malicious build. If the pinned commit ships a
beacon, the VM only makes its egress visible and mostly blocked. It does not buy
anything against a compromised model provider either — that is a data-handling
contract, not a control. And it does not know what you were authorised to scan;
the allowlist enforces exactly what you typed into it.

---

## 11. Verified build — 2026-11-07

`create-browser` was run end-to-end against the droplet at `<deploy-host>`,
then the VM was cold-booted to prove the containment survives a restart. Nine
things were wrong on the first pass; all are fixed in `lab-vms.sh`.

| Symptom | Cause | Fix |
|---|---|---|
| `There is no option group 'spice'` | `qemu-system-modules-spice` is a separate package on Ubuntu 24.04+ | added to `install_deps` |
| `Cannot access storage file ... Permission denied` | disk dir was `0750 root:root`; qemu runs as `libvirt-qemu` (group `kvm`) | `root:kvm` `0750`, images `0640` |
| egress pin vanished after reboot | rules were applied by cloud-init `runcmd` only | `/etc/artex/egress-pin.nft` + `artex-egress-pin.service`; `pin-egress` rewrites the file |
| `virsh start` → `Cannot access ... virtinst-*-cloudinit.iso` | `virt-install` deletes the seed ISO after first boot | `sanitize_domain` drops the cdrom from the persistent config |
| `nft: syntax error, unexpected 'meta'` | `meta` and `fwd` are reserved nft keywords, so `table inet meta` never parsed | renamed to `artex_meta` |
| NTP blocked, host-LAN rules missed | script hardcoded `192.168.122.0/24`; this host's default net is `192.168.123.0/24` | `net_vars` derives gateway and CIDR from `virsh net-dumpxml` |
| clipboard agent present | `ubuntu-desktop-minimal` depends on `spice-vdagent` | purge in `runcmd`, strip `spicevmc` channel + `redirdev` devices |
| hardened prefs had no effect | snap Firefox reads `~/snap/firefox/common/.mozilla` | profile seeded at both paths |
| `status` printed the pre-reboot address | `domifaddr --source lease` returns every lease, oldest first | `get_ip` picks the newest lease for the domain MAC |

Result after cold boot:

```
artex-egress-pin.service  active     # policy drop, only <droplet>:22
artex-tunnel.service      active     # ssh -N -L 127.0.0.1:8787
curl 127.0.0.1:8787/setup → 200
curl https://example.com  → blocked
curl <droplet>:8788       → blocked
spice-vdagent             → not installed
firefox (as web)          → -P artex http://127.0.0.1:8787/
```

Console: `virt-viewer --domain-name artex-browser` (SPICE on `127.0.0.1:5900`).

Note that the `redirdev` removal is what makes "no clipboard" true: with the
SPICE devices present, installing an agent later would silently reopen the
channel.
