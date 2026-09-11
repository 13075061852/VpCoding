#!/usr/bin/env bash
# Relay Control self-test.
#
#   bash selftest.sh                    full verification of an installed instance
#   bash selftest.sh --quick            services, ports and panel health only
#   bash selftest.sh --probe-dest H:P   probe one REALITY destination (used by install.sh)
#
# The full check proves the deployed instance really works: it injects a
# temporary client into the live config, completes a REALITY handshake against
# the running service, fetches a URL through the tunnel, confirms the
# StatsService API reports that user's traffic, then restores the original
# zero-state config. Any failure exits non-zero.
set -Eeuo pipefail
IFS=$'\n\t'

XRAY="${XRAY:-/usr/local/bin/xray}"
CONFIG="${CONFIG:-/etc/xray-att-relay/config.json}"
ENTRY_PORT="${ENTRY_PORT:-8443}"
PANEL_PORT="${PANEL_PORT:-8444}"
XRAY_SERVICE="${XRAY_SERVICE:-xray-att-relay}"
PANEL_SERVICE="${PANEL_SERVICE:-node-admin}"

MODE="full"
PROBE_DEST=""

usage() {
  cat <<'EOF'
Usage: bash selftest.sh [--quick] [--probe-dest HOST:PORT]
                        [--config PATH] [--entry-port N] [--panel-port N]

  --quick              check services, listening ports and the panel health endpoint
  --probe-dest H:P     start a throwaway REALITY server/client pair and verify that
                       destination completes a handshake (exit 0 = usable)
EOF
}
while (($#)); do
  case "$1" in
    --quick) MODE="quick"; shift ;;
    --probe-dest) PROBE_DEST="${2:?--probe-dest requires host:port}"; MODE="probe"; shift 2 ;;
    --config) CONFIG="${2:?--config requires a path}"; shift 2 ;;
    --entry-port) ENTRY_PORT="${2:?--entry-port requires a value}"; shift 2 ;;
    --panel-port) PANEL_PORT="${2:?--panel-port requires a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -x "$XRAY" ]] || { echo "selftest: $XRAY not found" >&2; exit 1; }

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

pass() { printf '  [ok]   %s\n' "$1"; }
fail() { printf '  [FAIL] %s\n' "$1" >&2; }

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

wait_port() {
  local port="$1" tries="${2:-30}" i
  for ((i = 0; i < tries; i++)); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  return 1
}

# Start a loopback HTTP target plus a throwaway REALITY client, then fetch the
# target through the tunnel. Returns 0 only when the whole chain works.
run_client_probe() {
  local sport="$1" sni="$2" pub="$3" sid="$4" uuid="$5"
  local cliport targetport cli_pid http_pid rc=1
  cliport="$(free_port)"
  targetport="$(free_port)"
  cat > "$WORK/client.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"tag": "probe-socks", "listen": "127.0.0.1", "port": ${cliport}, "protocol": "socks", "settings": {"auth": "noauth", "udp": false}}],
  "outbounds": [{
    "tag": "probe-out", "protocol": "vless",
    "settings": {"vnext": [{"address": "127.0.0.1", "port": ${sport}, "users": [{"id": "${uuid}", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "${sni}", "fingerprint": "chrome", "publicKey": "${pub}", "shortId": "${sid}", "spiderX": "/"}}
  }]
}
EOF
  python3 -m http.server "$targetport" --bind 127.0.0.1 >/dev/null 2>&1 &
  http_pid=$!
  "$XRAY" run -config "$WORK/client.json" >/dev/null 2>&1 &
  cli_pid=$!
  if wait_port "$cliport" 20; then
    if curl -fsS --max-time 15 -x "socks5h://127.0.0.1:${cliport}" "http://127.0.0.1:${targetport}/" -o /dev/null; then
      rc=0
    fi
  fi
  kill "$cli_pid" "$http_pid" 2>/dev/null || true
  wait "$cli_pid" 2>/dev/null || true
  wait "$http_pid" 2>/dev/null || true
  return $rc
}

# Spin a throwaway REALITY server with a fresh keypair and probe its dest.
probe_dest() {
  local dest="$1" host="${1%:*}" kp priv pub sid uuid sport srv_pid rc=1
  kp="$("$XRAY" x25519)"
  priv="$(awk -F': ' '/PrivateKey|Private key/{print $2; exit}' <<<"$kp")"
  pub="$(awk -F': ' '/PublicKey|Public key/{print $2; exit}' <<<"$kp")"
  sid="$(openssl rand -hex 8)"
  uuid="$("$XRAY" uuid)"
  sport="$(free_port)"
  cat > "$WORK/probe-server.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag": "probe-in", "listen": "127.0.0.1", "port": ${sport},
    "protocol": "vless",
    "settings": {"clients": [{"id": "${uuid}", "flow": "xtls-rprx-vision", "email": "probe"}], "decryption": "none"},
    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"show": false, "dest": "${dest}", "xver": 0, "serverNames": ["${host}"], "privateKey": "${priv}", "shortIds": ["${sid}"]}}
  }],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}]
}
EOF
  "$XRAY" run -config "$WORK/probe-server.json" >/dev/null 2>&1 &
  srv_pid=$!
  if wait_port "$sport" 20 && [[ -n "$priv" && -n "$pub" ]]; then
    if run_client_probe "$sport" "$host" "$pub" "$sid" "$uuid"; then rc=0; fi
  fi
  kill "$srv_pid" 2>/dev/null || true
  wait "$srv_pid" 2>/dev/null || true
  return $rc
}

if [[ "$MODE" == probe ]]; then
  if probe_dest "$PROBE_DEST"; then
    echo "REALITY destination usable: $PROBE_DEST"
    exit 0
  fi
  echo "REALITY destination failed: $PROBE_DEST" >&2
  exit 1
fi

echo 'Relay Control self-test'
rc=0

check_service() {
  if systemctl is-active --quiet "$1"; then pass "$1 active"; else fail "$1 not active"; rc=1; fi
}
check_service "$XRAY_SERVICE"
check_service "$PANEL_SERVICE"

check_listen() {
  local port="$1"
  if ss -lnt 2>/dev/null | awk 'NR>1{print $4}' | grep -qE "[:.]${port}\$"; then
    pass "TCP ${port} listening"
  elif (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
    pass "TCP ${port} reachable"
  else
    fail "TCP ${port} not listening"
    rc=1
  fi
}
check_listen "$ENTRY_PORT"
check_listen "$PANEL_PORT"

if curl -fsk --max-time 8 "https://127.0.0.1:${PANEL_PORT}/healthz" 2>/dev/null | grep -qx 'ok'; then
  pass "panel health endpoint https://127.0.0.1:${PANEL_PORT}/healthz"
else
  fail "panel health endpoint https://127.0.0.1:${PANEL_PORT}/healthz"
  rc=1
fi

if [[ "$MODE" == quick ]]; then
  if [[ -f "$CONFIG" ]] && ! python3 - "$CONFIG" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
services = (d.get('api') or {}).get('services') or []
level = ((d.get('policy') or {}).get('levels') or {}).get('0') or {}
ok = 'StatsService' in services and 'stats' in d and level.get('statsUserUplink') and level.get('statsUserDownlink')
sys.exit(0 if ok else 1)
PY
  then
    echo '  [warn] StatsService traffic accounting is not enabled in the Xray config' >&2
  fi
  echo 'Quick self-test finished.'
  exit "$rc"
fi

if [[ ! -f "$CONFIG" ]]; then
  fail "config not found: $CONFIG"
  exit 1
fi
mapfile -t RP < <(python3 - "$CONFIG" <<'PY'
import json, sys
rs = json.load(open(sys.argv[1]))['inbounds'][0]['streamSettings']['realitySettings']
print(rs['serverNames'][0])
print(rs['privateKey'])
print(rs['shortIds'][0])
PY
)
SERVER_NAME="${RP[0]:-}"
PRIVATE_KEY="${RP[1]:-}"
SHORT_ID="${RP[2]:-}"
if [[ -z "$SERVER_NAME" || -z "$PRIVATE_KEY" || -z "$SHORT_ID" ]]; then
  fail "could not read REALITY settings from $CONFIG"
  exit 1
fi

BACKUP="$WORK/config.backup"
cp -f "$CONFIG" "$BACKUP"
restore_config() {
  [[ -f "$BACKUP" ]] || return 0
  cp -f "$BACKUP" "$CONFIG"
  chown root:xray-att-relay "$CONFIG" 2>/dev/null || true
  chmod 0640 "$CONFIG"
  systemctl restart "$XRAY_SERVICE" >/dev/null 2>&1 || true
  rm -f "$BACKUP"
}
trap 'restore_config; cleanup' EXIT

TEST_UUID="$("$XRAY" uuid)"
python3 - "$CONFIG" "$TEST_UUID" <<'PY'
import json, sys
path, uuid = sys.argv[1], sys.argv[2]
data = json.load(open(path))
inbound = data['inbounds'][0]
inbound['settings'].setdefault('clients', []).append(
    {'id': uuid, 'flow': 'xtls-rprx-vision', 'email': '__selftest__'})
outbounds = data.setdefault('outbounds', [])
if not any(entry.get('tag') == 'direct' for entry in outbounds):
    outbounds.append({'tag': 'direct', 'protocol': 'freedom'})
# Pin the probe to the direct outbound so the loopback test target is reachable
# even when the instance already routes real clients through upstream nodes.
rule = {'type': 'field', 'user': ['__selftest__'], 'outboundTag': 'direct'}
if inbound.get('tag'):
    rule['inboundTag'] = [inbound['tag']]
rules = data.setdefault('routing', {}).setdefault('rules', [])
rules.insert(0, rule)
with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
    f.write('\n')
PY
chown root:xray-att-relay "$CONFIG" 2>/dev/null || true
chmod 0640 "$CONFIG"
systemctl restart "$XRAY_SERVICE"
if wait_port "$ENTRY_PORT" 40; then
  PUB="$("$XRAY" x25519 -i "$PRIVATE_KEY" | awk -F': ' '/PublicKey|Public key/{print $2; exit}')"
  if [[ -n "$PUB" ]] && run_client_probe "$ENTRY_PORT" "$SERVER_NAME" "$PUB" "$SHORT_ID" "$TEST_UUID"; then
    pass "REALITY handshake and proxied request through TCP ${ENTRY_PORT} (SNI ${SERVER_NAME})"
    counter=""
    for _ in {1..10}; do
      counter="$("$XRAY" api statsquery --server=127.0.0.1:10085 -pattern 'user>>>__selftest__' 2>/dev/null || true)"
      grep -q '__selftest__' <<<"$counter" && break
      sleep 0.5
    done
    if grep -q '__selftest__' <<<"$counter"; then
      pass "StatsService reports per-user traffic for __selftest__"
    else
      fail "StatsService did not report per-user traffic (api/stats/policy missing or API down)"
      rc=1
    fi
  else
    fail "REALITY handshake or proxied request through TCP ${ENTRY_PORT} (SNI ${SERVER_NAME})"
    rc=1
  fi
else
  fail "entry port ${ENTRY_PORT} not listening after restart"
  rc=1
fi
restore_config
if wait_port "$ENTRY_PORT" 40; then
  pass "zero-state config restored and entry port listening"
else
  fail "entry port ${ENTRY_PORT} not listening after restoring zero-state config"
  rc=1
fi

if [[ "$rc" -eq 0 ]]; then
  echo 'Self-test passed.'
else
  echo 'Self-test FAILED.' >&2
fi
exit "$rc"
