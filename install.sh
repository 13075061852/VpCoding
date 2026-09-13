#!/usr/bin/env bash
# Relay Control bootstrap installer. It creates a NEW instance only.
#
# Permission model (important):
#   /etc/xray-att-relay is owned by root and group xray-att-relay, mode 2750
#   (setgid). The service runs as xray-att-relay, so it must be able to
#   traverse the directory and read config.json. The setgid bit makes files the
#   panel later rewrites keep the xray-att-relay group.
#
# Traffic accounting:
#   The generated config enables the Xray StatsService API on 127.0.0.1:10085,
#   the "stats" counter store and per-user uplink/downlink accounting in policy
#   level 0. Without these the panel can create forwarding nodes but can never
#   read their traffic, so every node would permanently report 0 B.
set -Eeuo pipefail
IFS=$'\n\t'

RELAY_VERSION="1.1.0"
XRAY_VERSION="${XRAY_VERSION:-26.3.27}"
RELAY_REPO="${RELAY_REPO:-}"
PUBLIC_HOST="${PUBLIC_HOST:-}"
ADMIN_USER="${ADMIN_USER:-admin}"
REALITY_DEST="${REALITY_DEST:-}"
NON_INTERACTIVE=0
ENTRY_PORT=8443
PANEL_PORT=8444

# REALITY destinations are probed with a real handshake before one is written
# into the config, so an unreachable or version-incompatible target can never
# end up deployed. Some targets (for example www.microsoft.com) have been
# reported to break REALITY handshakes in recent Xray releases, and Xray itself
# warns that apple/icloud targets risk GFW blocking, so those go last.
REALITY_DEST_CANDIDATES=(
  "www.bing.com:443"
  "www.cloudflare.com:443"
  "www.amazon.com:443"
  "www.apple.com:443"
)

usage() {
  cat <<'EOF'
Usage:
  sudo bash install.sh [--host PUBLIC_IP_OR_DOMAIN] [--repo GIT_URL]
                       [--dest HOST:PORT] [--admin-user NAME]
                       [--xray-version VERSION] [--non-interactive]

Environment alternatives: PUBLIC_HOST, RELAY_REPO, ADMIN_USER, REALITY_DEST.
This installer refuses to overwrite an existing Relay/Xray installation.
EOF
}
while (($#)); do
  case "$1" in
    --host) PUBLIC_HOST="${2:?--host requires a value}"; shift 2 ;;
    --repo) RELAY_REPO="${2:?--repo requires a value}"; shift 2 ;;
    --dest) REALITY_DEST="${2:?--dest requires a value}"; shift 2 ;;
    --admin-user) ADMIN_USER="${2:?--admin-user requires a value}"; shift 2 ;;
    --xray-version) XRAY_VERSION="${2:?--xray-version requires a value}"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { echo 'Run as root (sudo bash install.sh).' >&2; exit 1; }
[[ "$ADMIN_USER" =~ ^[A-Za-z0-9_.-]{1,80}$ ]] || { echo 'Invalid admin user.' >&2; exit 1; }
[[ "$XRAY_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid Xray version.' >&2; exit 1; }
if [[ -n "$REALITY_DEST" ]]; then
  [[ "$REALITY_DEST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}$ ]] || { echo 'Provide --dest as host:port (for example www.apple.com:443).' >&2; exit 1; }
fi

if [[ -z "$PUBLIC_HOST" ]]; then
  PUBLIC_HOST="$(curl -4fsS --connect-timeout 5 --max-time 10 https://api.ipify.org || true)"
fi
[[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || { echo 'Provide a valid public IP or hostname with --host.' >&2; exit 1; }

if [[ -e /etc/node-admin/admin.json || -e /etc/xray-att-relay/config.json || -e /etc/systemd/system/node-admin.service ]]; then
  echo 'An existing Relay/Xray installation was found; refusing to overwrite it.' >&2
  echo 'Use update.sh for an existing Relay installation, or inspect/remove it manually.' >&2
  exit 1
fi

# Read os-release in a subshell so it cannot clobber this script's variables.
OS_ID="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")"
case "$OS_ID" in debian|ubuntu) ;; *) echo 'Only Debian/Ubuntu are supported by this bootstrap script.' >&2; exit 1;; esac

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl unzip openssl git python3 python3-qrcode

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"
TMP_REPO=''
# The EXIT trap must end with a command that succeeds, otherwise it would
# overwrite the installer's real exit status with a failure.
cleanup() {
  if [[ -n "$TMP_REPO" ]]; then rm -rf "$TMP_REPO"; fi
  return 0
}
trap cleanup EXIT
if [[ ! -f "$SOURCE_DIR/relay_admin/app.py" ]]; then
  [[ -n "$RELAY_REPO" ]] || { echo 'Installer was piped; provide --repo https://github.com/OWNER/REPO.git.' >&2; exit 1; }
  [[ "$RELAY_REPO" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$ ]] || { echo 'Only an HTTPS GitHub repository URL is accepted.' >&2; exit 1; }
  TMP_REPO="$(mktemp -d)"
  git clone --depth 1 "$RELAY_REPO" "$TMP_REPO/repo"
  SOURCE_DIR="$TMP_REPO/repo"
fi
for file in app.py operations.py console.css console.js delete-dialog.js login.js; do
  [[ -f "$SOURCE_DIR/relay_admin/$file" ]] || { echo "Package is missing relay_admin/$file" >&2; exit 1; }
done
[[ -f "$SOURCE_DIR/selftest.sh" ]] || { echo 'Package is missing selftest.sh' >&2; exit 1; }

ARCH="$(dpkg --print-architecture)"
[[ "$ARCH" == amd64 ]] || { echo "Unsupported architecture: $ARCH (amd64 required)." >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"; cleanup' EXIT
url="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"
curl -fL --retry 3 --connect-timeout 10 -o "$work/xray.zip" "$url"
expected="$(curl -fsSL --retry 3 "${url}.dgst" | awk '/SHA2-256/{print $NF; exit}')"
actual="$(sha256sum "$work/xray.zip" | awk '{print $1}')"
[[ "$expected" =~ ^[a-fA-F0-9]{64}$ && "$actual" == "$expected" ]] || { echo 'Xray release checksum verification failed.' >&2; exit 1; }
unzip -q "$work/xray.zip" -d "$work/xray"
install -m 0755 "$work/xray/xray" /usr/local/bin/xray

install -d -m 0750 /opt/node-admin
install -d -m 0700 /etc/node-admin /var/backups/node-admin /var/log/node-admin
install -d -m 0700 /etc/fastclient-subscription /etc/att-subscription
if ! id -u xray-att-relay >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin xray-att-relay
fi
# The Xray service runs as xray-att-relay: make the config directory traversable
# and the config group-readable, with setgid so panel rewrites keep the group.
install -d -m 0750 /etc/xray-att-relay
chown root:xray-att-relay /etc/xray-att-relay
chmod 2750 /etc/xray-att-relay

# Select a REALITY destination that actually completes a handshake.
if [[ -z "$REALITY_DEST" ]]; then
  echo 'Probing REALITY destinations...'
  for candidate in "${REALITY_DEST_CANDIDATES[@]}"; do
    if bash "$SOURCE_DIR/selftest.sh" --probe-dest "$candidate" >/dev/null 2>&1; then
      REALITY_DEST="$candidate"
      echo "  selected: $REALITY_DEST"
      break
    fi
    echo "  unavailable: $candidate" >&2
  done
fi
[[ -n "$REALITY_DEST" ]] || { echo 'No working REALITY destination found; pass --dest host:port.' >&2; exit 1; }
REALITY_SERVER_NAME="${REALITY_DEST%:*}"

keypair="$(/usr/local/bin/xray x25519)"
private_key="$(awk -F': ' '/PrivateKey|Private key/{print $2; exit}' <<<"$keypair")"
[[ -n "$private_key" ]] || { echo 'Could not generate Xray Reality key.' >&2; exit 1; }
short_id="$(openssl rand -hex 8)"
cat > /etc/xray-att-relay/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["StatsService"]},
  "stats": {},
  "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}}},
  "inbounds": [{
    "tag": "new-att-relay-in", "listen": "0.0.0.0", "port": ${ENTRY_PORT},
    "protocol": "vless",
    "settings": {"clients": [], "decryption": "none"},
    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
      "show": false, "dest": "${REALITY_DEST}", "xver": 0,
      "serverNames": ["${REALITY_SERVER_NAME}"], "privateKey": "${private_key}", "shortIds": ["${short_id}"]
    }}
  }],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {"domainStrategy": "AsIs", "rules": []}
}
EOF
chown root:xray-att-relay /etc/xray-att-relay/config.json
chmod 0640 /etc/xray-att-relay/config.json
/usr/local/bin/xray run -test -config /etc/xray-att-relay/config.json

if [[ "$PUBLIC_HOST" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then san="IP:${PUBLIC_HOST}"; else san="DNS:${PUBLIC_HOST}"; fi
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
  -keyout /etc/node-admin/key.pem -out /etc/node-admin/cert.pem \
  -subj "/CN=${PUBLIC_HOST}" -addext "subjectAltName=${san}" >/dev/null 2>&1
chmod 0600 /etc/node-admin/key.pem
chmod 0644 /etc/node-admin/cert.pem

credentials="$(python3 - "$ADMIN_USER" <<'PY'
import base64, hashlib, json, os, secrets, sys
user=sys.argv[1]
password=secrets.token_urlsafe(20)
salt=secrets.token_bytes(16)
iterations=310000
record={'username':user,'salt':base64.urlsafe_b64encode(salt).decode().rstrip('='),'password_hash':base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256',password.encode(),salt,iterations,32)).decode().rstrip('='),'iterations':iterations}
fd=os.open('/etc/node-admin/admin.json',os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w',encoding='utf-8') as f: json.dump(record,f,ensure_ascii=False,indent=2); f.write('\n')
print(user); print(password)
PY
)"
admin_user="$(sed -n '1p' <<<"$credentials")"
admin_password="$(sed -n '2p' <<<"$credentials")"

for file in app.py operations.py console.css console.js delete-dialog.js login.js; do
  install -m 0640 "$SOURCE_DIR/relay_admin/$file" "/opt/node-admin/$file"
done
cat > /etc/systemd/system/xray-att-relay.service <<'EOF'
[Unit]
Description=Xray relay managed by Relay Control
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=xray-att-relay
Group=xray-att-relay
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/xray run -config /etc/xray-att-relay/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/node-admin.service <<EOF
[Unit]
Description=Relay Control administration panel
After=network-online.target xray-att-relay.service
Wants=network-online.target
[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/node-admin
Environment=PUBLIC_HOST=${PUBLIC_HOST}
Environment=RELAY_LABEL=中转控制台
ExecStart=/usr/bin/python3 /opt/node-admin/app.py
Restart=on-failure
RestartSec=3
UMask=027
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
ProtectSystem=strict
ReadWritePaths=/etc/node-admin /etc/xray-att-relay /var/backups/node-admin /var/log/node-admin /etc/fastclient-subscription /etc/att-subscription
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now xray-att-relay
systemctl enable --now node-admin

# Both services must be healthy before the installer reports success.
if ! systemctl is-active --quiet xray-att-relay; then
  journalctl -u xray-att-relay -n 50 --no-pager >&2 || true
  echo 'xray-att-relay failed to start.' >&2
  exit 1
fi
if ! (exec 3<>"/dev/tcp/127.0.0.1/${ENTRY_PORT}") 2>/dev/null; then
  journalctl -u xray-att-relay -n 50 --no-pager >&2 || true
  echo "xray-att-relay is active but TCP ${ENTRY_PORT} is not listening." >&2
  exit 1
fi
for _ in {1..30}; do
  if curl -fsk --max-time 3 "https://127.0.0.1:${PANEL_PORT}/healthz" 2>/dev/null | grep -qx 'ok'; then break; fi
  sleep 1
done
curl -fsk --max-time 5 "https://127.0.0.1:${PANEL_PORT}/healthz" | grep -qx 'ok' || { journalctl -u node-admin -n 50 --no-pager >&2 || true; echo 'node-admin health check failed.' >&2; exit 1; }
systemctl is-active --quiet node-admin || { echo 'node-admin is not active.' >&2; exit 1; }

# Real end-to-end proof: inject a temporary client, complete a REALITY
# handshake through the live service, then restore the zero-state config.
echo 'Running end-to-end self-test...'
bash "$SOURCE_DIR/selftest.sh"

cat > /root/relay-admin-credentials.txt <<EOF
Relay Control initial credentials — store offline, then delete this file.
URL: https://${PUBLIC_HOST}:${PANEL_PORT}
Username: ${admin_user}
Password: ${admin_password}
Xray entry port: ${ENTRY_PORT}
REALITY destination: ${REALITY_DEST}
Installed version: ${RELAY_VERSION}
EOF
chmod 0600 /root/relay-admin-credentials.txt
cat <<EOF

Installed and verified successfully.
Management URL: https://${PUBLIC_HOST}:${PANEL_PORT}
Username: ${admin_user}
Password: ${admin_password}
Xray entry port: ${ENTRY_PORT}
REALITY destination: ${REALITY_DEST}

Credentials are also in /root/relay-admin-credentials.txt (mode 0600).
Open TCP ${ENTRY_PORT} and ${PANEL_PORT} in your cloud firewall/security group. Change the admin password after first login.
EOF
