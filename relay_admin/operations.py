"""Administrative operations. No credentials or subscription URLs enter the audit log."""
import json
import os
import re
import secrets
import tarfile
import tempfile
import threading
import time
from collections import deque

LOCK = threading.RLock()
AUDIT = '/var/log/node-admin/audit.jsonl'
BACKUPS = '/var/backups/node-admin'
ACTIONS = {'/node/add': '添加节点', '/node/save': '编辑节点', '/node/delete': '删除节点',
           '/node/default': '切换默认节点', '/node/test': '检测节点', '/node/test-all': '检测全部节点',
           '/forward/create': '创建转发', '/forward/title': '修改订阅名称', '/forward/delete': '删除转发',
           '/client/add': '添加客户端', '/client/toggle': '切换客户端状态', '/client/delete': '删除客户端',
           '/feeds/rotate': '轮换订阅令牌', '/account/password': '修改密码', '/service/restart': '重启转发服务',
           '/ops/backup': '创建安全备份', '/ops/sessions/revoke': '退出其他会话'}


def record(action, success, peer=''):
    if action not in ACTIONS:
        return
    entry = {'time': int(time.time()), 'action': ACTIONS[action], 'ok': bool(success), 'peer': str(peer)[:64]}
    try:
        with LOCK:
            os.makedirs(os.path.dirname(AUDIT), mode=0o700, exist_ok=True)
            if os.path.exists(AUDIT) and os.path.getsize(AUDIT) > 2 * 1024 * 1024:
                os.replace(AUDIT, AUDIT + '.1')
            fd = os.open(AUDIT, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except OSError:
        # Logging failures must not misreport an already committed mutation as failed.
        print('node-admin: audit write failed', flush=True)


def events():
    with LOCK:
        try:
            with open(AUDIT, encoding='utf-8') as f:
                return [json.loads(line) for line in reversed(deque(f, maxlen=80))]
        except (OSError, ValueError):
            return []


def backups():
    os.makedirs(BACKUPS, mode=0o700, exist_ok=True)
    items = []
    for name in os.listdir(BACKUPS):
        if re.fullmatch(r'console-\d{8}-\d{6}-[a-f0-9]{8}\.tar\.gz', name):
            st = os.stat(os.path.join(BACKUPS, name))
            items.append({'name': name, 'size': st.st_size, 'time': int(st.st_mtime)})
    return sorted(items, key=lambda item: (item['time'], item['name']), reverse=True)


def create_backup(configs, state_file, app_dir):
    with LOCK:
        os.makedirs(BACKUPS, mode=0o700, exist_ok=True)
        name = time.strftime('console-%Y%m%d-%H%M%S-') + secrets.token_hex(4) + '.tar.gz'
        fd, temporary = tempfile.mkstemp(prefix='.console-', dir=BACKUPS)
        os.close(fd)
        try:
            with tarfile.open(temporary, 'w:gz') as archive:
                paths = [app_dir, os.path.dirname(state_file), '/etc/systemd/system/node-admin.service']
                paths += [os.path.dirname(cfg['path']) for cfg in configs.values()]
                paths += ['/etc/systemd/system/' + cfg['service'] for cfg in configs.values()]
                def clean(info):
                    if '__pycache__' in info.name or '.before-' in info.name:
                        return None
                    return info
                for path in sorted(set(paths)):
                    if os.path.exists(path):
                        archive.add(path, arcname=path.lstrip('/'), filter=clean)
            with open(temporary, 'rb') as f:
                os.fsync(f.fileno())
            os.replace(temporary, os.path.join(BACKUPS, name))
            # Only rotate backups created by this feature; preserve pre-upgrade archives.
            for item in backups()[10:]:
                os.unlink(os.path.join(BACKUPS, item['name']))
            return name
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
