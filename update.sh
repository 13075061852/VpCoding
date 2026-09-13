#!/usr/bin/env bash
# Updates only Relay Control application files. It never writes Xray or /etc/node-admin configuration.
set -Eeuo pipefail
IFS=$'\n\t'
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -f /etc/node-admin/admin.json && -f /etc/xray-att-relay/config.json ]] || { echo 'No Relay Control installation found.' >&2; exit 1; }
for file in app.py operations.py console.css console.js delete-dialog.js login.js; do
  [[ -f "$SOURCE_DIR/relay_admin/$file" ]] || { echo "Missing $file" >&2; exit 1; }
done
python3 -m py_compile "$SOURCE_DIR/relay_admin/app.py" "$SOURCE_DIR/relay_admin/operations.py"
python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import app' "$SOURCE_DIR/relay_admin"
backup="/var/backups/node-admin/app-update-$(date +%Y%m%d-%H%M%S)-$$"
exec 9>/run/relay-admin-update.lock
flock -n 9 || { echo 'Another update is running.' >&2; exit 1; }
install -d -m 0700 "$backup"
cp /opt/node-admin/app.py /opt/node-admin/operations.py /opt/node-admin/console.css /opt/node-admin/console.js /opt/node-admin/delete-dialog.js /opt/node-admin/login.js "$backup/"
rollback() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "$status" -ne 0 ]]; then
    echo "Update failed; restoring application backup: $backup" >&2
    if cp "$backup"/* /opt/node-admin/ && systemctl restart node-admin; then
      echo 'Previous application files restored; checking recovery.' >&2
      curl -fsk --retry 10 --retry-connrefused --retry-delay 1 --max-time 3 https://127.0.0.1:8444/healthz >&2 || echo 'Recovery health check failed; inspect node-admin logs.' >&2
    else
      echo 'Recovery failed; inspect node-admin logs and restore the backup manually.' >&2
    fi
  fi
  exit "$status"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for file in app.py operations.py console.css console.js delete-dialog.js login.js; do
  install -m 0640 "$SOURCE_DIR/relay_admin/$file" "/opt/node-admin/$file.new"
  mv "/opt/node-admin/$file.new" "/opt/node-admin/$file"
done
systemctl restart node-admin
healthy=0
for _ in {1..30}; do
  if curl -fsk --max-time 3 https://127.0.0.1:8444/healthz 2>/dev/null | grep -qx ok; then
    healthy=1
    break
  fi
  systemctl is-active --quiet node-admin || break
  sleep 1
done
if [[ "$healthy" -ne 1 ]]; then
  echo 'Updated panel did not become healthy.' >&2
  exit 1
fi
if [[ -f "$SOURCE_DIR/selftest.sh" ]]; then
  bash "$SOURCE_DIR/selftest.sh" --quick
fi
trap - EXIT INT TERM
echo "Updated Relay Control. Backup: $backup"
