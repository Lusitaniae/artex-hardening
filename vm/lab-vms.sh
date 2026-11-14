#!/usr/bin/env bash
# lab-vms.sh — KVM VMs for driving an untrusted ARTEX build safely.
#
#   ./lab-vms.sh create-browser   # local headful browser VM (app lives in DO)
#   ./lab-vms.sh create-app       # local headless app VM (offline dry runs)
#   ./lab-vms.sh create           # both
#   ./lab-vms.sh pin-egress <ip>  # re-pin browser egress (droplet IP changed)
#   ./lab-vms.sh pin-egress --show | --open
#   ./lab-vms.sh status
#   ./lab-vms.sh console [browser|app]
#   ./lab-vms.sh destroy
#
# Design: the hypervisor boundary is the control. The guest OS is chosen for
# boringness, not for cleverness. Never put the browser in the same kernel as
# the app — a browser exploit would then land next to the Docker socket.
#
# If the app is a DigitalOcean droplet, you only need create-browser. Pass
# TUNNEL_HOST=<droplet-ip> so the browser VM's egress is pinned to one port.
# You can change it later without rebuilding:  pin-egress <new-ip>

set -euo pipefail

IMG_DIR="${IMG_DIR:-$HOME/vm-images}"
APP_NAME="${APP_NAME:-artex-app}"
BR_NAME="${BR_NAME:-artex-browser}"

APP_CPU=4; APP_MEM=8192; APP_DISK=24
BR_CPU=2;  BR_MEM=4096; BR_DISK=18

SERIES="${SERIES:-26.04}"
BASE_IMG="$IMG_DIR/ubuntu-$SERIES-server-cloudimg-amd64.img"
BASE_URL="https://cloud-images.ubuntu.com/releases/$SERIES/release/ubuntu-$SERIES-server-cloudimg-amd64.img"

# Disks must live where libvirt's AppArmor profile allows and where the qemu
# user can read them. Cloud-init seed files stay in $HOME; virt-install reads
# those as you and writes the ISO itself.
LIBVIRT_DIR="${LIBVIRT_DIR:-/var/lib/libvirt/images/artex-lab}"

NET_NAME="${NET_NAME:-default}"

ADMIN_KEY="$HOME/.ssh/artex_lab_ed25519"
TUNNEL_KEY="$HOME/.ssh/artex_tunnel_ed25519"

# Set this to the DO droplet's public IP to pin the browser VM's egress to
# exactly one destination: <ip>:22. Everything else is dropped, including DNS.
# Unset = not pinned (fine for a lab, wrong for an untrusted UI).
TUNNEL_HOST="${TUNNEL_HOST:-}"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- preflight
preflight() {
  [[ -e /dev/kvm ]] || die "/dev/kvm missing — enable nested virt on the outer host"
  grep -qE '\b(vmx|svm)\b' /proc/cpuinfo || die "no hardware virt exposed to this host"
  local free_gb; free_gb=$(df -BG --output=avail "$HOME" | tail -1 | tr -dc '0-9')
  (( free_gb >= APP_DISK + BR_DISK + 10 )) \
    || die "need $((APP_DISK+BR_DISK+10))G free under \$HOME, have ${free_gb}G"
  if ! id -nG | grep -qwE 'libvirt|kvm'; then
    warn "you are not in the libvirt/kvm groups."
    warn "run: sudo usermod -aG libvirt,kvm $USER   then log out and back in"
    die  "re-run this script afterwards"
  fi
}

install_deps() {
  # qemu-system-modules-spice is split out on Ubuntu 24.04+; without it
  # `--graphics spice` fails with "There is no option group 'spice'".
  local pkgs=(qemu-system-x86 qemu-system-modules-spice qemu-system-gui
              libvirt-daemon-system libvirt-clients virtinst
              cloud-image-utils genisoimage)
  local missing=()
  for p in "${pkgs[@]}"; do dpkg -s "$p" &>/dev/null || missing+=("$p"); done
  if (( ${#missing[@]} )); then
    log "installing: ${missing[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y "${missing[@]}"
  fi
  systemctl is-active --quiet libvirtd || sudo systemctl enable --now libvirtd
}

ensure_keys() {
  mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
  if [[ ! -f "$ADMIN_KEY" ]]; then
    log "generating lab admin key"
    ssh-keygen -q -t ed25519 -N '' -C "artex-lab-admin" -f "$ADMIN_KEY"
  fi
  if [[ ! -f "$TUNNEL_KEY" ]]; then
    log "generating tunnel-only key"
    ssh-keygen -q -t ed25519 -N '' -C "artex-tunnel" -f "$TUNNEL_KEY"
  fi
}

fetch_base() {
  mkdir -p "$IMG_DIR"
  if [[ ! -f "$BASE_IMG" ]]; then
    log "downloading $BASE_URL"
    curl -fL --progress-bar "$BASE_URL" -o "$BASE_IMG.part" || {
      warn "26.04 image not found; set SERIES=24.04 and retry"
      rm -f "$BASE_IMG.part"; exit 1; }
    mv "$BASE_IMG.part" "$BASE_IMG"
  fi
  # Stage a root-owned copy where qemu can actually read it. qemu runs as
  # libvirt-qemu, which is in the `kvm` group; a 0750 root:root directory is
  # not traversable by it, and virt-install then fails with
  # "Cannot access storage file ... Permission denied" after the download.
  sudo mkdir -p "$LIBVIRT_DIR"
  sudo chown root:kvm "$LIBVIRT_DIR" 2>/dev/null || sudo chown root:root "$LIBVIRT_DIR"
  sudo chmod 0750 "$LIBVIRT_DIR"
  if [[ ! -f "$LIBVIRT_DIR/base.qcow2" ]]; then
    log "staging base image into $LIBVIRT_DIR"
    sudo install -m 0640 -g kvm "$BASE_IMG" "$LIBVIRT_DIR/base.qcow2" \
      || sudo install -m 0644 "$BASE_IMG" "$LIBVIRT_DIR/base.qcow2"
  fi
}

# libvirt's default NAT network is often 192.168.122.0/24 but not always —
# this host uses 192.168.123.0/24. Hardcoding it means the NTP accept rule
# points at a gateway that doesn't exist and the "drop the host LAN" rules
# miss the real subnet, so derive both from the live network definition.
net_vars() {
  if [[ -z ${NET_GW:-} || -z ${NET_CIDR:-} ]]; then
    local pair gw mask
    pair=$(virsh net-dumpxml "$NET_NAME" 2>/dev/null \
      | sed -n "s/.*<ip address='\([0-9.]*\)' netmask='\([0-9.]*\)'.*/\1 \2/p" | head -1)
    if [[ -n $pair ]]; then
      gw=${pair%% *}; mask=${pair##* }
      NET_GW=$gw
      NET_CIDR=$(python3 -c 'import ipaddress,sys
print(ipaddress.ip_network("%s/%s" % (sys.argv[1], sys.argv[2]), strict=False))' "$gw" "$mask")
    fi
  fi
  NET_GW=${NET_GW:-192.168.122.1}
  NET_CIDR=${NET_CIDR:-192.168.122.0/24}
}

# ------------------------------------------------------------- cloud-init
# The tunnel key is restricted server-side. Note the three parts:
#   restrict     -> no pty, no agent, no X11, no user-rc
#   port-forwarding,permitopen -> allow exactly one destination
#   command=/bin/false -> even a session request cannot get a shell
# `-N -L 127.0.0.1:8787:127.0.0.1:8787` still works; a shell does not.
tunnel_key_line() {
  printf 'restrict,port-forwarding,permitopen="127.0.0.1:8787",command="/bin/false" %s' \
    "$(cat "$TUNNEL_KEY.pub")"
}

write_app_userdata() {
  local d="$IMG_DIR/$APP_NAME"; mkdir -p "$d"
  net_vars
  cat >"$d/user-data" <<YAML
#cloud-config
hostname: $APP_NAME
users:
  - default
  - name: ops
    groups: [sudo, docker]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$ADMIN_KEY.pub")
  - name: tunnel
    shell: /bin/bash
    lock_passwd: true
    no_create_home: false
package_update: true
packages:
  - docker.io
  - docker-compose-v2
  - nftables
  - tcpdump
  - conntrack
  - openssh-server
  - ca-certificates
  - jq
write_files:
  - path: /home/tunnel/.ssh/authorized_keys
    owner: tunnel:tunnel
    permissions: '0600'
    content: |
      $(tunnel_key_line)
  - path: /etc/ssh/sshd_config.d/10-artex.conf
    permissions: '0644'
    content: |
      PasswordAuthentication no
      PermitRootLogin no
      AllowTcpForwarding remote
      X11Forwarding no
      AllowAgentForwarding no
runcmd:
  - systemctl enable --now docker
  - systemctl restart ssh || systemctl restart sshd
  # metadata service, blocked at the host level (not just inside the bridge)
  - nft add table inet artex_meta
  - nft 'add chain inet artex_meta out { type filter hook output priority -10; policy accept; }'
  - nft add rule inet artex_meta out ip daddr 169.254.169.254 drop
  # stop the guest from wandering into the host's LAN or the other VMs
  - nft add table inet lan
  - nft add chain inet lan out '{ type filter hook output priority -5; policy accept; }'
  - nft add rule inet lan out ip daddr $NET_CIDR drop
  - nft add rule inet lan out ip daddr 10.0.0.0/8 drop
  - nft add rule inet lan out ip daddr 172.16.0.0/12 drop
  # 192.168.122.1 is the libvirt gateway; remove this accept if you never NAT
  - nft insert rule inet lan out ip daddr $NET_GW accept
  - touch /var/lib/cloud/instance/artex-ready
YAML
  cat >"$d/meta-data" <<YAML
instance-id: $APP_NAME-$(date +%s)
local-hostname: $APP_NAME
YAML
}

write_browser_userdata() {
  local d="$IMG_DIR/$BR_NAME"; mkdir -p "$d"
  net_vars

  # The browser itself only ever talks to 127.0.0.1:8787. Its sole real egress
  # need is the SSH tunnel. So anything that is not loopback, DHCP, NTP-to-
  # gateway, or <TUNNEL_HOST>:22 is dropped. No DNS means DNS cannot exfil.
  #
  # The pin is a file + unit, not a runcmd: nft rules applied at first boot
  # vanish on the first reboot, which silently re-opens the VM. `pin-egress`
  # rewrites the same file, so a manual repin also survives a reboot.
  local browser_files
  browser_files=$(cat <<FILES
  # The browser user has no password, so an idle-locked screen cannot be
  # unlocked from the console. Turn locking off in the system dconf database,
  # not per session.
  - path: /etc/dconf/profile/user
    permissions: '0644'
    content: |
      user-db:user
      system-db:local
  - path: /etc/dconf/db/local.d/00-artex-no-lock
    permissions: '0644'
    content: |
      [org/gnome/desktop/screensaver]
      lock-enabled=false

      [org/gnome/desktop/session]
      idle-delay=uint32 0
  - path: /home/web/.config/autostart/artex-browser.desktop
    owner: web:web
    permissions: '0644'
    content: |
      [Desktop Entry]
      Type=Application
      Name=ARTEX UI
      Comment=Local UI over the restricted SSH tunnel
      Exec=firefox -P artex --no-remote http://127.0.0.1:8787/
      X-GNOME-Autostart-enabled=true
  # Snap Firefox ignores ~/.mozilla: its HOME is ~/snap/firefox/common.
  - path: /home/web/snap/firefox/common/.mozilla/firefox/profiles.ini
    owner: web:web
    permissions: '0644'
    content: |
      [Profile0]
      Name=artex
      IsRelative=1
      Path=artex
      Default=1

      [General]
      StartWithLastProfile=1
      Version=2
  - path: /home/web/snap/firefox/common/.mozilla/firefox/artex/user.js
    owner: web:web
    permissions: '0644'
    content: |
      // ARTEX browser VM: one profile, one origin, no credential storage.
      user_pref("browser.startup.page", 1);
      user_pref("browser.startup.homepage", "http://127.0.0.1:8787/");
      user_pref("signon.rememberSignons", false);
      user_pref("browser.formfill.enable", false);
      user_pref("identity.fxaccounts.enabled", false);
      user_pref("datareporting.policy.dataSubmissionEnabled", false);
      user_pref("toolkit.telemetry.enabled", false);
      user_pref("app.update.auto", false);
      user_pref("extensions.autoDisableScopes", 15);
  # Same profile again for a non-snap Firefox, which reads ~/.mozilla.
  - path: /home/web/.mozilla/firefox/profiles.ini
    owner: web:web
    permissions: '0644'
    content: |
      [Profile0]
      Name=artex
      IsRelative=1
      Path=artex
      Default=1

      [General]
      StartWithLastProfile=1
      Version=2
  - path: /home/web/.mozilla/firefox/artex/user.js
    owner: web:web
    permissions: '0644'
    content: |
      user_pref("signon.rememberSignons", false);
      user_pref("browser.formfill.enable", false);
      user_pref("identity.fxaccounts.enabled", false);
      user_pref("browser.startup.homepage", "http://127.0.0.1:8787/");
FILES
)
  local pin_files='' pin_runcmd
  if [[ -n $TUNNEL_HOST ]]; then
    pin_files=$(cat <<FILES
  - path: /etc/artex/egress-pin.nft
    permissions: '0644'
    content: |
      table inet br {
        chain out {
          type filter hook output priority filter; policy drop;
          ct state established,related accept
          oifname "lo" accept
          udp sport 68 udp dport 67 accept
          ip daddr $NET_GW udp dport 123 accept
          ip daddr $TUNNEL_HOST tcp dport 22 accept
        }
      }
  - path: /etc/systemd/system/artex-egress-pin.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Apply browser VM egress pin (tunnel host only)
      DefaultDependencies=no
      After=network-pre.target
      Before=network-online.target

      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=-/usr/sbin/nft delete table inet br
      ExecStart=-/usr/sbin/nft -f /etc/artex/egress-pin.nft

      [Install]
      WantedBy=multi-user.target
FILES
)
    pin_runcmd='  - systemctl daemon-reload
  - systemctl enable --now artex-egress-pin.service'
  else
    pin_runcmd='  - echo "WARNING: browser egress NOT pinned (rebuild with TUNNEL_HOST=<droplet-ip>)"'
  fi

  cat >"$d/user-data" <<YAML
#cloud-config
hostname: $BR_NAME
users:
  - default
  - name: ops
    groups: [sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$ADMIN_KEY.pub")
  # Firefox runs as this user. It cannot read ops' SSH keys, so a browser
  # compromise does not hand over the tunnel credential.
  - name: web
    shell: /bin/bash
    lock_passwd: true
package_update: true
packages:
  - ubuntu-desktop-minimal
  - firefox
  - dconf-cli
  - openssh-server
  - nftables
  # ubuntu-desktop-minimal pulls spice-vdagent in as a dependency, which is a
  # clipboard/drag-and-drop channel into the guest. Purge it in runcmd below
  # and strip the spicevmc device from the domain XML.
write_files:
$browser_files
$pin_files
runcmd:
  - systemctl set-default graphical.target
  # Log the desktop straight in as the "web" user: the console is the browser.
  - |
    if ! grep -q '^AutomaticLogin=web' /etc/gdm3/custom.conf; then
      sed -i 's/^\[daemon\]/[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=web/' /etc/gdm3/custom.conf
    fi
  # freeze snap auto-refresh so the browser doesn't change mid-engagement
  - snap refresh --hold || true
  - apt-get purge -y spice-vdagent || true
  - dconf update
  - nft add table inet artex_meta
  - nft 'add chain inet artex_meta out { type filter hook output priority -10; policy accept; }'
  - nft add rule inet artex_meta out ip daddr 169.254.169.254 drop
$pin_runcmd
YAML
  cat >"$d/meta-data" <<YAML
instance-id: $BR_NAME-$(date +%s)
local-hostname: $BR_NAME
YAML
}

# --------------------------------------------------------------- create
create_vm() {
  local name=$1 cpu=$2 mem=$3 disk=$4 graphics=$5
  if virsh dominfo "$name" &>/dev/null; then
    warn "$name already exists; skipping (use destroy to rebuild)"
    return 0
  fi
  local ud="$IMG_DIR/$name/user-data" md="$IMG_DIR/$name/meta-data"
  local qcow="$LIBVIRT_DIR/$name.qcow2"

  # Overlay, not a copy: the base stays pristine and shared. Passing the base
  # image to virt-install with size= would resize it in place and corrupt the
  # other VM, which is the bug this comment exists to prevent.
  if [[ ! -f "$qcow" ]]; then
    log "creating overlay $qcow (${disk}G, backing base.qcow2)"
    sudo qemu-img create -q -f qcow2 -F qcow2 -b "$LIBVIRT_DIR/base.qcow2" "$qcow" "${disk}G"
    # group kvm: libvirt-qemu is in it, root:root 0644 is unreadable to qemu
    sudo chown root:kvm "$qcow" 2>/dev/null || sudo chown root:root "$qcow"
    sudo chmod 0640 "$qcow"
  fi

  local console_args=()
  [[ $graphics == none ]] && console_args=(--console pty,target_type=serial)

  log "creating $name (${cpu}vCPU / ${mem}MB / ${disk}G)"
  virt-install --quiet --name "$name" \
    --memory "$mem" --vcpus "$cpu" --cpu host-passthrough \
    --disk "path=$qcow,format=qcow2,bus=virtio" \
    --os-variant ubuntu24.04 \
    --network network=default,model=virtio \
    --graphics "$graphics" "${console_args[@]}" \
    --cloud-init "user-data=$ud,meta-data=$md" \
    --import --noautoconsole
  sanitize_domain "$name"
}

sanitize_domain() {
  # virt-install's defaults for a spice guest leave three things behind:
  #   * a spicevmc channel and two spicevmc redirdev (USB redirection) devices
  #     -- device pass-through paths into the guest that the design says it
  #     does not have;
  #   * a cdrom pointing at /var/lib/libvirt/boot/virtinst-*-cloudinit.iso,
  #     which virt-install deletes after the first boot, so the next cold
  #     `virsh start` fails with "Cannot access storage file".
  # cloud-init has already run by then; the seed does not need to stay.
  local name=$1 xml
  xml=$(mktemp)
  virsh dumpxml --inactive "$name" >"$xml" 2>/dev/null || { rm -f "$xml"; return 0; }
  python3 - "$xml" <<'PYEOF' || { rm -f "$xml"; return 0; }
import sys, xml.etree.ElementTree as ET
p = sys.argv[1]
t = ET.parse(p); r = t.getroot(); dev = r.find("devices")
if dev is None:
    sys.exit(0)
for el in list(dev.findall("channel")):
    if el.get("type") == "spicevmc":
        dev.remove(el)
for el in list(dev.findall("redirdev")):
    if el.get("type") == "spicevmc":
        dev.remove(el)
for el in list(dev.findall("disk")):
    src = el.find("source")
    if el.get("device") == "cdrom" and src is not None \
       and "cloudinit.iso" in (src.get("file") or ""):
        dev.remove(el)
t.write(p, encoding="utf-8", xml_declaration=True)
PYEOF
  virsh define "$xml" >/dev/null && rm -f "$xml"
}

get_ip() {
  # domifaddr returns every lease ever handed out, oldest first, so after a
  # reboot it can hand back the previous address. Prefer the newest lease for
  # this domain's MAC, and fall back to domifaddr if the MAC is unknown.
  local name=$1 mac ip=''
  mac=$(virsh dumpxml --inactive "$name" 2>/dev/null \
        | sed -n "s/.*<mac address='\([^']*\)'.*/\1/p" | head -1)
  if [[ -n $mac ]]; then
    ip=$(virsh net-dhcp-leases "$NET_NAME" 2>/dev/null \
         | awk -v m="${mac,,}" 'tolower($3) == m && $4 == "ipv4" {print $5}' \
         | cut -d/ -f1 | tail -1)
  fi
  [[ -n $ip ]] || ip=$(virsh domifaddr "$name" --source lease 2>/dev/null \
        | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -1)
  printf '%s' "$ip"
}

br_ip() {
  local ip; ip=$(get_ip "$BR_NAME" || true)
  [[ -n $ip ]] || die "$BR_NAME has no lease — is it running? (./vm/lab-vms.sh status)"
  printf '%s' "$ip"
}

remote() {
  ssh -i "$ADMIN_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
      "ops@$(br_ip)" "$@"
}

wait_ip() {
  local name=$1 ip=''
  for _ in $(seq 1 60); do
    ip=$(get_ip "$name")
    [[ -n $ip ]] && { echo "$ip"; return 0; }
    sleep 2
  done
  return 1
}

report() {
  local app_ip br_ip
  net_vars
  app_ip=$(wait_ip "$APP_NAME") || app_ip="(pending)"
  br_ip=$(wait_ip "$BR_NAME")  || br_ip="(pending)"
  cat <<EOM

  VM IPs on libvirt NAT ($NET_CIDR)
    app      $app_ip
    browser  $br_ip

  ssh ops@$app_ip   -i $ADMIN_KEY
  ssh ops@$br_ip    -i $ADMIN_KEY
  virt-viewer --domain-name $BR_NAME      # browser display (SPICE, local only)

  Next: read vm/README.md, then run the canary before anything else.
EOM
}

cmd_create_all() {
  preflight; install_deps; ensure_keys; fetch_base
  write_app_userdata; write_browser_userdata
  create_vm "$APP_NAME" "$APP_CPU" "$APP_MEM" "$APP_DISK" "none"
  create_vm "$BR_NAME"  "$BR_CPU"  "$BR_MEM"  "$BR_DISK"  "spice,listen=127.0.0.1"
  report
}

cmd_create_app() {
  preflight; install_deps; ensure_keys; fetch_base
  write_app_userdata
  create_vm "$APP_NAME" "$APP_CPU" "$APP_MEM" "$APP_DISK" "none"
  report
}

cmd_create_browser() {
  preflight; install_deps; ensure_keys; fetch_base
  write_browser_userdata
  create_vm "$BR_NAME" "$BR_CPU" "$BR_MEM" "$BR_DISK" "spice,listen=127.0.0.1"
  report
  if [[ -z $TUNNEL_HOST ]]; then
    warn "egress is NOT pinned. Rebuild with:"
    warn "  TUNNEL_HOST=<droplet-ip> ./vm/lab-vms.sh destroy && ... create-browser"
  fi
}

cmd_status() {
  virsh list --all
  for n in "$APP_NAME" "$BR_NAME"; do
    printf '%-14s %s\n' "$n" "$(get_ip "$n" || true)"
  done
}

# pin-egress <ip> | --show | --open
# Re-pin without rebuilding: droplet IPs change when you rebuild the droplet.
# Applied atomically with `nft -f`, so there is no window where the policy is
# half-written. The SSH session doing the applying survives: its replies match
# `ct state established,related`.
cmd_pin() {
  local arg="${1:-}"
  net_vars
  case "$arg" in
    --show|"")
      remote "sudo nft list table inet br" 2>/dev/null \
        || warn "no pin table on $BR_NAME — egress is OPEN"
      return 0 ;;
    --open)
      # Also remove the file and disable the unit, or the next reboot puts the
      # pin straight back and "open" quietly stops meaning open.
      remote "sudo rm -f /etc/artex/egress-pin.nft; sudo systemctl disable --now artex-egress-pin.service 2>/dev/null || true; sudo nft delete table inet br 2>/dev/null || true"
      warn "egress UNPINNED on $BR_NAME — re-pin before you browse untrusted UI"
      return 0 ;;
  esac

  local ip="$arg"
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "not an IPv4 literal: $ip"
  log "pinning $BR_NAME egress -> $ip:22"
  # Write the file the boot unit reads, then restart it. Applying the ruleset
  # only in the live kernel would be undone by the next reboot.
  remote "sudo install -d -m 0755 /etc/artex && sudo tee /etc/artex/egress-pin.nft >/dev/null && sudo systemctl restart artex-egress-pin.service 2>/dev/null || sudo nft -f /etc/artex/egress-pin.nft" <<EOF
table inet br {
  chain out {
    type filter hook output priority filter; policy drop;
    ct state established,related accept
    oifname "lo" accept
    udp sport 68 udp dport 67 accept
    ip daddr $NET_GW udp dport 123 accept
    ip daddr $ip tcp dport 22 accept
  }
}
EOF
  cmd_pin --show
}

cmd_console() {
  local name=${1:-app}
  [[ $name == app ]] && name=$APP_NAME
  [[ $name == browser ]] && name=$BR_NAME
  exec virt-viewer --domain-name "$name"
}

cmd_destroy() {
  for n in "$APP_NAME" "$BR_NAME"; do
    if virsh dominfo "$n" &>/dev/null; then
      log "destroying $n"
      virsh destroy "$n" &>/dev/null || true
      virsh undefine "$n" --remove-all-storage --nvram &>/dev/null || \
        virsh undefine "$n" --remove-all-storage
    fi
    # belt and braces: undefine can leave the overlay behind
    [[ -f "$LIBVIRT_DIR/$n.qcow2" ]] && sudo rm -f "$LIBVIRT_DIR/$n.qcow2"
  done
  log "VMs gone. Base image kept at $LIBVIRT_DIR/base.qcow2"
}

case "${1:-}" in
  create)         cmd_create_all ;;
  create-app)     cmd_create_app ;;
  create-browser) cmd_create_browser ;;
  pin-egress)     cmd_pin "${2:-}" ;;
  status)         cmd_status ;;
  console)        cmd_console "${2:-browser}" ;;
  destroy)        cmd_destroy ;;
  *) sed -n '2,19p' "$0"; exit 1 ;;
esac
