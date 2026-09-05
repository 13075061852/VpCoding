#!/usr/bin/env bash
# Relay Control bootstrap installer. It creates a NEW instance only.
set -Eeuo pipefail
IFS=$'\n\t'

VERSION="1.0.0"
XRAY_VERSION="26.3.27"
RELAY_REPO="${RELAY_REPO:-}"
PUBLIC_HOST="${PUBLIC_HOST:-}"
ADMIN_USER="${ADMIN_USER:-admin}"
NON_INTERACTIVE=0

usage() {
  cat <<'EOF'
Usage:
  sudo bash install.sh [--host PUBLIC_IP_OR_DOMAIN] [--repo GIT_URL] [--non-interactive]

Environment alternatives: PUBLIC_HOST, RELAY_REPO, ADMIN_USER.
This installer refuses to overwrite an existing Relay/Xray installation.
EOF
}
while (($#)); do
  case "$1" in
    --host) PUBLIC_HOST="${2:?--host requires a value}"; shift 2 ;;
    --repo) RELAY_REPO="${2:?--repo requires a value}"; shift 2 ;;
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

if [[ -z "$PUBLIC_HOST" ]]; then
  PUBLIC_HOST="$(curl -4fsS --connect-timeout 5 --max-time 10 https://api.ipify.org || true)"
fi
[[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || { echo 'Provide a valid public IP or hostname with --host.' >&2; exit 1; }

if [[ -e /etc/node-admin/admin.json || -e /etc/xray-att-relay/config.json || -e /etc/systemd/system/node-admin.service ]]; then
  echo 'An existing Relay/Xray installation was found; refusing to overwrite it.' >&2
  echo 'Use update.sh for an existing Relay installation, or inspect/remove it manually.' >&2
  exit 1
fi

if [[ -r /etc/os-release ]]; then . /etc/os-release; else ID=''; fi
case "${ID:-}" in debian|ubuntu) ;; *) echo 'Only Debian/Ubuntu are supported by this bootstrap script.' >&2; exit 1;; esac

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl unzip openssl git python3 python3-qrcode

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"
TMP_REPO=''
cleanup() { [[ -n "$TMP_REPO" ]] && rm -rf "$TMP_REPO"; }
trap cleanup EXIT
if [[ ! -f "$SOURCE_DIR/relay_admin/app.py" ]]; then
  [[ -n "$RELAY_REPO" ]] || { echo 'Installer was piped; provide --repo https://github.com/OWNER/REPO.git.' >&2; exit 1; }
  [[ "$RELAY_REPO" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$ ]] || { echo 'Only an HTTPS GitHub repository URL is accepted.' >&2; exit 1; }
  TMP_REPO="$(mktemp -d)"
  git clone --depth 1 "$RELAY_REPO" "$TMP_REPO/repo"
  SOURCE_DIR="$TMP_REPO/repo"
fi
for file in app.py operations.py console.css console.js delete-dialog.js; do
  [[ -f "$SOURCE_DIR/relay_admin/$file" ]] || { echo "Package is missing relay_admin/$file" >&2; exit 1; }
done

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
install -d -m 0700 /etc/node-admin /etc/xray-att-relay /var/backups/node-admin /var/log/node-admin
install -d -m 0700 /etc/fastclient-subscription /etc/att-subscription
if ! id -u xray-att-relay >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin xray-att-relay
fi

keypair="$(/usr/local/bin/xray x25519)"
private_key="$(awk -F': ' '/PrivateKey|Private key/{print $2; exit}' <<<"$keypair")"
[[ -n "$private_key" ]] || { echo 'Could not generate Xray Reality key.' >&2; exit 1; }
short_id="$(openssl rand -hex 8)"
cat > /etc/xray-att-relay/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag": "new-att-relay-in", "listen": "0.0.0.0", "port": 8443,
    "protocol": "vless",
    "settings": {"clients": [], "decryption": "none"},
    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
      "show": false, "dest": "www.microsoft.com:443", "xver": 0,
      "serverNames": ["www.microsoft.com"], "privateKey": "${private_key}", "shortIds": ["${short_id}"]
    }}
  }],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {"domainStrategy": "AsIs", "rules": []}
}
EOF
chmod 0644 /etc/xray-att-relay/config.json
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

for file in app.py operations.py console.css console.js delete-dialog.js; do
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
systemctl enable --now xray-att-relay node-admin
for _ in {1..15}; do
  if curl -fsk --max-time 3 "https://127.0.0.1:8444/healthz" | grep -qx 'ok'; then break; fi
  sleep 1
done
curl -fsk --max-time 5 "https://127.0.0.1:8444/healthz" | grep -qx 'ok' || { journalctl -u node-admin -n 50 --no-pager >&2; exit 1; }

cat > /root/relay-admin-credentials.txt <<EOF
Relay Control initial credentials — store offline, then delete this file.
URL: https://${PUBLIC_HOST}:8444
Username: ${admin_user}
Password: ${admin_password}
Xray entry port: 8443
Installed version: ${VERSION}
EOF
chmod 0600 /root/relay-admin-credentials.txt
cat <<EOF

Installed successfully.
Management URL: https://${PUBLIC_HOST}:8444
Username: ${admin_user}
Password: ${admin_password}

Credentials are also in /root/relay-admin-credentials.txt (mode 0600).
Open TCP 8443 and 8444 in your cloud firewall/security group. Change the admin password after first login.
EOF
