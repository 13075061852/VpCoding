#!/usr/bin/env bash
# Updates only Relay Control application files. It never writes Xray or /etc/node-admin configuration.
set -Eeuo pipefail
IFS=$'\n\t'
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -f /etc/node-admin/admin.json && -f /etc/xray-att-relay/config.json ]] || { echo 'No Relay Control installation found.' >&2; exit 1; }
for file in app.py operations.py console.css console.js delete-dialog.js; do
  [[ -f "$SOURCE_DIR/relay_admin/$file" ]] || { echo "Missing $file" >&2; exit 1; }
done
python3 -m py_compile "$SOURCE_DIR/relay_admin/app.py" "$SOURCE_DIR/relay_admin/operations.py"
backup="/var/backups/node-admin/app-update-$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$backup"
cp /opt/node-admin/app.py /opt/node-admin/operations.py /opt/node-admin/console.css /opt/node-admin/console.js /opt/node-admin/delete-dialog.js "$backup/"
for file in app.py operations.py console.css console.js delete-dialog.js; do
  install -m 0640 "$SOURCE_DIR/relay_admin/$file" "/opt/node-admin/$file.new"
  mv "/opt/node-admin/$file.new" "/opt/node-admin/$file"
done
if ! systemctl restart node-admin || ! curl -fsk --max-time 10 https://127.0.0.1:8444/healthz | grep -qx ok; then
  cp "$backup"/* /opt/node-admin/
  systemctl restart node-admin
  echo "Update failed and was rolled back: $backup" >&2
  exit 1
fi
echo "Updated Relay Control. Backup: $backup"
