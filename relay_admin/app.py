#!/usr/bin/env python3
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, timedelta
import hashlib
import hmac
import html
import http.cookies
import json
import os
import platform
import re
import secrets
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit, urlencode
import qrcode
import operations
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
import qrcode.image.svg

AUTH_FILE = '/etc/node-admin/admin.json'
STATE_FILE = '/etc/node-admin/state.json'
CERT_FILE = '/etc/node-admin/cert.pem'
KEY_FILE = '/etc/node-admin/key.pem'
BACKUP_DIR = '/var/backups/node-admin'
PUBLIC_HOST = os.environ.get('PUBLIC_HOST', '').strip()
RELAY_LABEL = os.environ.get('RELAY_LABEL', '中转控制台').strip() or '中转控制台'
PORT = 8444
XRAY = '/usr/local/bin/xray'
SOCKS_PORT_START = 20000
SOCKS_PORT_END = 20999
FASTCLIENT_REVOKED_PATHS_FILE = '/etc/fastclient-subscription/revoked-paths.json'
ATT_SUBSCRIPTION_REVOKED_PATHS_FILE = '/etc/att-subscription/revoked-paths.json'
FASTCLIENT_TITLE_PATHS_FILE = '/etc/fastclient-subscription/subscription-titles.json'
ATT_SUBSCRIPTION_TITLE_PATHS_FILE = '/etc/att-subscription/subscription-titles.json'
VALID_FASTCLIENT_SUBSCRIPTION_PATH = re.compile(r'^/subscribe/[A-Za-z0-9_-]{8,160}$')
VIEW_PATHS = {'nodes-view': '/nodes', 'forward-view': '/forward', 'host-view': '/host'}
PATH_VIEWS = {path: view for view, path in VIEW_PATHS.items()}

CONFIGS = {
    'att': {'service': 'xray-att-relay.service', 'path': '/etc/xray-att-relay/config.json', 'inbound': 'new-att-relay-in', 'entry': 8443},
}
COUNTRY_HINTS = {
    'direct': '本机直连',
    'vircs-att': '美国',
    'latest-us-att': '美国',
    'ipfly-uae': '新加坡（配置标签 UAE；本次实测）',
    'indonesia-att': '印度尼西亚',
    'taiwan-residential': '台湾',
}
MANAGED_PROTOCOLS = {'vless', 'http', 'socks'}
VALID_TAG = re.compile(r'^[A-Za-z0-9_.-]{1,80}$')
VALID_ADDRESS = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$')
MAX_REQUEST_THREADS = 32
MAX_LOGIN_IPS = 2048
LOGIN_WINDOW = 300
LOGIN_LIMIT = 5
SESSIONS = {}
LOGIN_FAILURES = {}
MUTEX = threading.RLock()


def esc(value):
    return html.escape(str(value), quote=True)


def latency_markup(value):
    """Render latency with a stable visual tier: <=120ms, <=200ms, and slower."""
    try:
        latency = float(value)
    except (TypeError, ValueError):
        return '—'
    if not 0 <= latency:
        return '—'
    tier = 'low' if latency <= 120 else ('medium' if latency <= 200 else 'high')
    text = '%dms' % round(latency)
    return '<span class="latency %s">%s</span>' % (tier, text)


def load_auth():
    with open(AUTH_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def verify_password(password):
    try:
        auth = load_auth()
        salt = base64.urlsafe_b64decode(auth['salt'] + '==')
        expected = base64.urlsafe_b64decode(auth['password_hash'] + '==')
        iterations = int(auth.get('iterations', 310000))
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, 32)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def change_admin_password(current_password, new_password, confirmation):
    if not verify_password(current_password):
        raise ValueError('当前密码不正确')
    if len(new_password) < 10:
        raise ValueError('新密码至少需要 10 个字符')
    if len(new_password) > 256:
        raise ValueError('新密码长度不能超过 256 个字符')
    if new_password != confirmation:
        raise ValueError('两次输入的新密码不一致')
    with MUTEX:
        auth = load_auth()
        iterations = int(auth.get('iterations', 310000))
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), salt, iterations, 32)
        auth['salt'] = base64.urlsafe_b64encode(salt).decode().rstrip('=')
        auth['password_hash'] = base64.urlsafe_b64encode(password_hash).decode().rstrip('=')
        auth['iterations'] = iterations
        atomic_write(AUTH_FILE, json.dumps(auth, ensure_ascii=False, indent=2).encode('utf-8'))


def atomic_write(path, data, mode=0o600):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.node-admin-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_state():
    with MUTEX:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                state = json.load(f)
        else:
            state = {'version': 3, 'feeds': {}, 'disabled_clients': {}, 'client_meta': {}, 'node_meta': {}, 'forward_meta': {}, 'sessions': {}}
        state.setdefault('version', 2)
        state.setdefault('feeds', {})
        state.setdefault('disabled_clients', {})
        state.setdefault('client_meta', {})
        state.setdefault('node_meta', {})
        state.setdefault('forward_meta', {})
        state.setdefault('sessions', {})
        for feed in ('all', *CONFIGS):
            state['feeds'].setdefault(feed, secrets.token_urlsafe(32))
        changed = False
        for item in state['forward_meta'].values():
            if item.get('mode') == 'subscription' and not isinstance(item.get('subscription_token'), str):
                item['subscription_token'] = secrets.token_urlsafe(32)
                item['legacy_shared_feed'] = True
                changed = True
        for key, cfg in CONFIGS.items():
            data = read_config(cfg)
            inbound = next((x for x in data.get('inbounds', []) if x.get('tag') == cfg['inbound']), None)
            if not inbound:
                continue
            for client in inbound.get('settings', {}).get('clients', []):
                ckey = client_key(key, client)
                if ckey not in state['client_meta']:
                    state['client_meta'][ckey] = {'label': client.get('email') or ckey.rsplit('::', 1)[-1], 'created': int(time.time())}
                    changed = True
        if changed or not os.path.exists(STATE_FILE):
            save_state(state)
        return state


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), mode=0o700, exist_ok=True)
    payload = (json.dumps(state, ensure_ascii=False, indent=2) + '\n').encode()
    atomic_write(STATE_FILE, payload, 0o600)


def revoke_external_subscription(url, provider='fastclient'):
    path = urlsplit(url or '').path
    if not VALID_FASTCLIENT_SUBSCRIPTION_PATH.fullmatch(path):
        raise ValueError('外部订阅地址无效，无法安全撤销')
    files = {'fastclient': FASTCLIENT_REVOKED_PATHS_FILE, 'att-subscription': ATT_SUBSCRIPTION_REVOKED_PATHS_FILE}
    revoked_file = files.get(provider)
    if not revoked_file:
        raise ValueError('未知外部订阅提供方')
    paths = set()
    try:
        with open(revoked_file, 'r', encoding='utf-8') as handle:
            document = json.load(handle)
    except FileNotFoundError:
        document = {}
    except (OSError, ValueError) as exc:
        raise RuntimeError('无法读取外部订阅撤销列表：' + str(exc))
    existing = document.get('paths', []) if isinstance(document, dict) else []
    if not isinstance(existing, list) or not all(isinstance(item, str) for item in existing):
        raise RuntimeError('外部订阅撤销列表格式无效')
    paths.update(existing); paths.add(path)
    payload = (json.dumps({'version': 1, 'paths': sorted(paths)}, ensure_ascii=False, indent=2) + '\n').encode()
    atomic_write(revoked_file, payload, 0o644)

def update_external_subscription_title(item, title):
    provider = item.get('subscription_provider', 'fastclient')
    files = {'fastclient': FASTCLIENT_TITLE_PATHS_FILE, 'att-subscription': ATT_SUBSCRIPTION_TITLE_PATHS_FILE}
    title_file = files.get(provider)
    path = urlsplit(item.get('url', '')).path
    if not title_file or not VALID_FASTCLIENT_SUBSCRIPTION_PATH.fullmatch(path):
        raise ValueError('外部订阅记录不完整，无法同步名称')
    try:
        with open(title_file, 'r', encoding='utf-8') as handle:
            document = json.load(handle)
    except FileNotFoundError:
        document = {}
    except (OSError, ValueError) as exc:
        raise RuntimeError('无法读取订阅名称配置：' + str(exc))
    titles = document.get('titles', {}) if isinstance(document, dict) else {}
    if not isinstance(titles, dict):
        raise RuntimeError('订阅名称配置格式无效')
    titles[path] = title
    atomic_write(title_file, (json.dumps({'version': 1, 'titles': titles}, ensure_ascii=False, indent=2) + '\n').encode(), 0o644)


def rename_external_forward(form):
    ident = form.get('id', '').strip()
    title = form.get('title', '').strip()
    if not ident or not title or len(title) > 80 or '\n' in title or '\r' in title:
        raise ValueError('订阅名称不能为空，且最长 80 个字符')
    with MUTEX:
        state = load_state()
        item = state.get('forward_meta', {}).get(ident)
        if not item or item.get('mode') not in ('external_subscription', 'subscription'):
            raise ValueError('仅 FastClient 订阅支持修改名称')
        if item.get('mode') == 'external_subscription':
            update_external_subscription_title(item, title)
        item['label'] = title
        save_state(state)
    return title


def save_persistent_session(sid, csrf, expires):
    """Keep the opted-in browser session across a controlled service restart."""
    with MUTEX:
        state = load_state()
        now = time.time()
        sessions = {k: v for k, v in state['sessions'].items() if v.get('expires', 0) > now}
        sessions[sid] = {'csrf': csrf, 'expires': expires}
        state['sessions'] = sessions
        save_state(state)


def remove_persistent_session(sid):
    with MUTEX:
        state = load_state()
        if state['sessions'].pop(sid, None) is not None:
            save_state(state)


def client_key(config_key, client):
    return config_key + '::' + (client.get('email') or client.get('id', 'unknown'))


def read_config(cfg):
    with open(cfg['path'], 'r', encoding='utf-8') as f:
        return json.load(f)


def validate_config_references(data):
    inbound_tags = {item.get('tag') for item in data.get('inbounds', [])}
    outbound_tags = {item.get('tag') for item in data.get('outbounds', [])}
    for rule in data.get('routing', {}).get('rules', []):
        outbound = rule.get('outboundTag')
        if outbound and outbound not in outbound_tags and outbound != data.get('api', {}).get('tag'):
            raise ValueError('路由引用了不存在的出站：' + outbound)
        missing = [tag for tag in rule.get('inboundTag', []) if tag not in inbound_tags]
        if missing:
            raise ValueError('路由引用了不存在的入站：' + '、'.join(missing))


def wait_service_healthy(cfg, timeout=5):
    deadline = time.monotonic() + timeout
    last = ''
    while time.monotonic() < deadline:
        active, _ = service_state(cfg['service'])
        last = active
        if active == 'active':
            try:
                with socket.create_connection(('127.0.0.1', cfg['entry']), timeout=.5):
                    return
            except OSError:
                pass
        time.sleep(.2)
    raise RuntimeError('服务未恢复健康状态（systemd=%s，端口=%s 未监听）' % (last or 'unknown', cfg['entry']))


def write_config_json(cfg, data):
    validate_config_references(data)
    path = cfg['path']
    old_bytes = open(path, 'rb').read()
    old_mode = stat.S_IMODE(os.stat(path).st_mode)
    new_bytes = (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode()
    fd, tmp = tempfile.mkstemp(prefix='.node-admin-test-', suffix='.json', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(new_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, old_mode)
        check = subprocess.run([XRAY, 'run', '-test', '-config', tmp], capture_output=True, text=True, timeout=20)
        if check.returncode != 0:
            detail = (check.stdout + '\n' + check.stderr).strip()[-1200:]
            raise RuntimeError('Xray 配置校验失败：' + detail)
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        backup = os.path.join(BACKUP_DIR, '%s-%d-%s.json' % (
            cfg['service'].replace('.service', ''), time.time_ns(), secrets.token_hex(3)))
        atomic_write(backup, old_bytes, old_mode)
        os.replace(tmp, path)
        restarted = subprocess.run(['systemctl', 'restart', cfg['service']], capture_output=True, text=True, timeout=25)
        try:
            if restarted.returncode != 0:
                raise RuntimeError((restarted.stderr or restarted.stdout).strip()[-800:])
            wait_service_healthy(cfg)
        except Exception as exc:
            atomic_write(path, old_bytes, old_mode)
            subprocess.run(['systemctl', 'restart', cfg['service']], capture_output=True, timeout=25)
            try:
                wait_service_healthy(cfg)
            except Exception:
                pass
            raise RuntimeError('服务重启失败，已自动回滚：' + str(exc))
        return old_bytes, old_mode, backup
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def restore_config(cfg, old_bytes, old_mode):
    atomic_write(cfg['path'], old_bytes, old_mode)
    subprocess.run(['systemctl', 'restart', cfg['service']], capture_output=True, timeout=25)
    wait_service_healthy(cfg)


def commit_config_and_state(cfg, data, state):
    old_state = open(STATE_FILE, 'rb').read() if os.path.exists(STATE_FILE) else None
    old_state_mode = stat.S_IMODE(os.stat(STATE_FILE).st_mode) if old_state is not None else 0o600
    old_bytes, old_mode, backup = write_config_json(cfg, data)
    try:
        save_state(state)
    except Exception:
        restore_config(cfg, old_bytes, old_mode)
        if old_state is None:
            try:
                os.unlink(STATE_FILE)
            except FileNotFoundError:
                pass
        else:
            atomic_write(STATE_FILE, old_state, old_state_mode)
        raise
    return old_bytes, old_mode, backup


def service_state(service):
    unit = subprocess.run(['systemctl', 'show', service, '--property=LoadState', '--value'], capture_output=True, text=True, timeout=5)
    if unit.stdout.strip() == 'not-found':
        return 'not-found', 'not-found'
    active = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True, timeout=5)
    enabled = subprocess.run(['systemctl', 'is-enabled', service], capture_output=True, text=True, timeout=5)
    return active.stdout.strip() or active.stderr.strip(), enabled.stdout.strip() or enabled.stderr.strip()


def find_inbound(data, cfg):
    return next((x for x in data.get('inbounds', []) if x.get('tag') == cfg['inbound']), None)


def find_outbound(data, tag):
    return next((x for x in data.get('outbounds', []) if x.get('tag') == tag), None)


def route_info(data, tag):
    result = []
    for rule in data.get('routing', {}).get('rules', []):
        if rule.get('outboundTag') == tag:
            result.append({'users': rule.get('user', []), 'inbounds': rule.get('inboundTag', []), 'network': rule.get('network', 'TCP/UDP')})
    return result


def fallback_tag(data, cfg):
    for rule in data.get('routing', {}).get('rules', []):
        if rule.get('inboundTag') == [cfg['inbound']] and not rule.get('user') and not rule.get('network'):
            return rule.get('outboundTag')
    return None


def set_fallback(data, cfg, tag):
    rules = data.setdefault('routing', {}).setdefault('rules', [])
    for rule in rules:
        if rule.get('inboundTag') == [cfg['inbound']] and not rule.get('user') and not rule.get('network'):
            rule['outboundTag'] = tag
            return
    rules.append({'type': 'field', 'inboundTag': [cfg['inbound']], 'outboundTag': tag})


def endpoint(outbound):
    protocol = outbound.get('protocol', '')
    s = outbound.get('settings', {})
    if protocol == 'vless':
        if s.get('address'):
            return s['address'], s.get('port', '')
        if s.get('vnext'):
            return s['vnext'][0].get('address', ''), s['vnext'][0].get('port', '')
    if protocol in ('http', 'socks'):
        if s.get('address'):
            return s['address'], s.get('port', '')
        if s.get('servers'):
            z = s['servers'][0]
            return z.get('address', z.get('server', '')), z.get('port', '')
    return '', ''


def outbound_proxy_auth(outbound):
    """Return credentials without ever including them in an HTML response."""
    settings = outbound.get('settings', {})
    if settings.get('servers'):
        user = (settings['servers'][0].get('users') or [{}])[0]
        return user.get('user', ''), user.get('pass', '')
    return settings.get('user', ''), settings.get('pass', '')


def node_inventory(state):
    nodes = []
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        active, enabled = service_state(cfg['service'])
        default = fallback_tag(data, cfg)
        for outbound in data.get('outbounds', []):
            tag = outbound.get('tag', '')
            protocol = outbound.get('protocol', '')
            if not tag or protocol not in MANAGED_PROTOCOLS:
                continue
            address, port = endpoint(outbound)
            meta = state.get('node_meta', {}).get(key + '::' + tag, {})
            username, _ = outbound_proxy_auth(outbound)
            nodes.append({'config': key, 'service': cfg['service'], 'entry': cfg['entry'], 'inbound': cfg['inbound'], 'tag': tag, 'protocol': protocol, 'address': address, 'port': port, 'username': username, 'user': meta.get('user', ''), 'country': meta.get('country', COUNTRY_HINTS.get(tag, '未标注')), 'activated_on': meta.get('activated_on', ''), 'duration_days': meta.get('duration_days', ''), 'expires_on': meta.get('expires_on', ''), 'routes': route_info(data, tag), 'default': default == tag, 'active': active, 'enabled': enabled})
    return nodes


def client_rows(state):
    """Each row: link label + entry + outbound chain (tag/ip/port/country/how) + vless link."""
    rows = []
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        inbound = find_inbound(data, cfg)
        if not inbound:
            continue
        present = {client_key(key, c): c for c in inbound.get('settings', {}).get('clients', [])}
        keys = list(present)
        for ckey, item in state.get('disabled_clients', {}).items():
            if item.get('config') == key and item.get('inbound') == cfg['inbound'] and ckey not in present:
                keys.append(ckey)
        for ckey in keys:
            client = present.get(ckey)
            if client is None:
                item = state['disabled_clients'].get(ckey, {})
                client = item.get('client', {})
            if not client:
                continue
            meta = state.get('client_meta', {}).get(ckey, {})
            # FastClient's migrated credentials are private implementation
            # details and must never leak into the generic VLESS feed.
            if meta.get('hidden'):
                continue
            label = meta.get('label') or client.get('email') or ckey.rsplit('::', 1)[-1]
            tag, addr, port, country, how = client_route_for(key, client.get('email'), data, cfg)
            rows.append({'key': ckey, 'config': key, 'entry': cfg['entry'], 'inbound': cfg['inbound'],
                         'label': label, 'client': client, 'enabled': ckey in present,
                         'out_tag': tag, 'out_addr': addr, 'out_port': port, 'out_country': country, 'route_how': how,
                         'link': make_vless_link(cfg, inbound, client, label)})
    return rows


def client_route_for(config_key, client_email, data, cfg):
    """Return (outbound_tag, endpoint_addr, endpoint_port, country, how) for a client."""
    for rule in data.get('routing', {}).get('rules', []):
        users = rule.get('user', [])
        if client_email and client_email in users:
            tag = rule.get('outboundTag', '')
            outbound = find_outbound(data, tag)
            if outbound is not None:
                addr, port = endpoint(outbound)
                return tag, addr, port, country_of(config_key, tag), '按用户路由'
    default = fallback_tag(data, cfg)
    if default:
        outbound = find_outbound(data, default)
        if outbound is not None:
            addr, port = endpoint(outbound)
            return default, addr, port, country_of(config_key, default), '入口默认'
    return 'direct', '', '', '本机直连', 'Xray 默认出站'

def country_of(config_key, tag, state=None):
    state = state if state is not None else load_state()
    meta = state.get('node_meta', {}).get(config_key + '::' + tag, {})
    if meta.get('country'):
        return meta['country']
    data = read_config(CONFIGS[config_key])
    outbound = find_outbound(data, tag)
    protocol = (outbound or {}).get('protocol', '')
    if protocol in ('http', 'socks'):
        addr, _ = endpoint(outbound)
        if addr:
            return geo_lookup(addr)
    return meta.get('country') or COUNTRY_HINTS.get(tag, '未标注')


def geo_lookup(addr):
    cache = GEO_CACHE.get(addr)
    if cache and time.time() - cache[0] < 86400:
        return cache[1]
    country = None
    try:
        result = subprocess.run(
            ['curl', '-s', '--max-time', '4', 'http://ip-api.com/line/%s?fields=country' % addr],
            capture_output=True, text=True, timeout=8)
        value = (result.stdout or '').strip()
        if result.returncode == 0 and value and value.lower() != 'fail':
            country = translate_country(value)
    except Exception:
        pass
    if country is None:
        try:
            result = subprocess.run(['getent', 'hosts', addr], capture_output=True, text=True, timeout=4)
            if result.returncode != 0 or not result.stdout.strip():
                raise ValueError
            ip = result.stdout.split()[0]
            result = subprocess.run(
                ['curl', '-s', '--max-time', '4', 'http://ip-api.com/line/%s?fields=country' % ip],
                capture_output=True, text=True, timeout=8)
            value = (result.stdout or '').strip()
            if result.returncode == 0 and value and value.lower() != 'fail':
                country = translate_country(value)
        except Exception:
            country = None
    if country is None:
        country = COUNTRY_HINTS.get(addr, '')
    GEO_CACHE[addr] = (time.time(), country)
    return country


GEO_CACHE = {}

CN_NAMES = {'United States': '美国', 'Japan': '日本', 'Singapore': '新加坡', 'Taiwan': '台湾', 'China': '中国',
            'Hong Kong': '香港', 'Indonesia': '印度尼西亚', 'United Arab Emirates': '阿联酋', 'South Korea': '韩国',
            'United Kingdom': '英国', 'Germany': '德国', 'Canada': '加拿大', 'Australia': '澳大利亚',
            'Netherlands': '荷兰', 'France': '法国', 'Russia': '俄罗斯', 'India': '印度', 'Brazil': '巴西',
            'Vietnam': '越南', 'Thailand': '泰国', 'Malaysia': '马来西亚', 'Philippines': '菲律宾'}


def translate_country(name):
    return CN_NAMES.get(name, name)

def derive_public_key(reality):
    private = reality.get('privateKey', '')
    if not private:
        return ''
    result = subprocess.run([XRAY, 'x25519', '-i', private], capture_output=True, text=True, timeout=10)
    match = re.search(r'Password \(PublicKey\):\s*([A-Za-z0-9_-]+)', result.stdout)
    return match.group(1) if match else ''


def make_vless_link(cfg, inbound, client, label):
    try:
        stream = inbound.get('streamSettings', {})
        reality = stream.get('realitySettings', {})
        public_key = derive_public_key(reality)
        server_name = (reality.get('serverNames') or [''])[0]
        short_id = (reality.get('shortIds') or [''])[0]
        if not public_key or not client.get('id'):
            return '[无法生成：Reality 公钥或客户端 ID 缺失]'
        params = {'type': 'tcp', 'encryption': 'none', 'security': 'reality', 'pbk': public_key, 'fp': 'chrome', 'sni': server_name, 'sid': short_id, 'spx': '/', 'flow': client.get('flow', 'xtls-rprx-vision')}
        return 'vless://%s@%s:%s?%s#%s' % (quote(client['id'], safe=''), PUBLIC_HOST, cfg['entry'], urlencode(params, quote_via=quote), quote(label, safe=''))
    except Exception as exc:
        return '[无法生成链接：%s]' % exc


def make_qr_svg(value):
    """Create a local SVG QR code; proxy credentials never leave this host."""
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )
    qr.add_data(value)
    qr.make(fit=True)
    image = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    return image.to_string(encoding='unicode').encode('utf-8')


def make_subscription(state, scope, output_format):
    rows = client_rows(state)
    if scope in ('main', 'att'):
        rows = [x for x in rows if x['config'] == scope]
    links = [x['link'] for x in rows if x['enabled'] and x['link'].startswith('vless://')]
    raw = '\n'.join(links) + ('\n' if links else '')
    if output_format in ('vless', 'raw'):
        return raw.encode()
    return base64.b64encode(raw.encode()).decode().encode()


def yaml_string(value):
    # JSON string syntax is also a safe quoted YAML scalar.
    return json.dumps(str(value), ensure_ascii=False)


def subscription_userinfo(state, item):
    """Build FastClient subscription usage metadata.

    This controls what FastClient displays on the subscription card. Xray traffic
    accounting is not enabled here, so upload/download default to values stored
    on the forwarding record or 0; quota defaults to 500 GB. Expiry follows the
    earliest selected upstream node expiry date, or 30 days from now if unknown.
    """
    total = int(item.get('quota_total_bytes') or 500 * 1024 * 1024 * 1024)
    upload = int(item.get('quota_upload_bytes') or 0)
    download = int(item.get('quota_download_bytes') or 0)
    expire = int(item.get('quota_expire') or 0)
    if not expire:
        dates = []
        for node in item.get('subscription_nodes') or []:
            if not isinstance(node, dict):
                continue
            key = (node.get('config') or item.get('config') or 'att') + '::' + (node.get('upstream') or '')
            expires_on = state.get('node_meta', {}).get(key, {}).get('expires_on')
            if expires_on:
                try:
                    dates.append(date.fromisoformat(expires_on))
                except ValueError:
                    pass
        if dates:
            expire = int(time.mktime(min(dates).timetuple()))
        else:
            expire = int(time.mktime((date.today() + timedelta(days=30)).timetuple()))
    return 'upload=%d; download=%d; total=%d; expire=%d' % (upload, download, total, expire)


def make_fastclient_forward_subscription(state, item):
    # Build a FastClient YAML profile. Each selected upstream gets one proxy.
    rows_by_key = {record['key']: record for record in client_rows(state) if record['enabled']}
    selected_nodes = item.get('subscription_nodes')
    if not isinstance(selected_nodes, list) or not selected_nodes:
        selected_nodes = [{'client_key': item.get('client_key', ''), 'label': item.get('label', '')}]
    profiles = []
    used_names = set()
    for node in selected_nodes:
        if not isinstance(node, dict):
            return None
        row = rows_by_key.get(node.get('client_key', ''))
        if not row:
            return None
        cfg = CONFIGS.get(row.get('config'))
        if not cfg:
            return None
        data = read_config(cfg)
        inbound = find_inbound(data, cfg)
        if not inbound:
            return None
        stream = inbound.get('streamSettings', {})
        reality = stream.get('realitySettings', {})
        public_key = derive_public_key(reality)
        server_name = (reality.get('serverNames') or [''])[0]
        short_id = (reality.get('shortIds') or [''])[0]
        client = row.get('client', {})
        profile_name = str(node.get('label') or row.get('label') or item.get('label') or 'FastClient 节点').strip()
        if not public_key or not server_name or not client.get('id') or not profile_name or profile_name in used_names:
            return None
        used_names.add(profile_name)
        profiles.append({
            'name': profile_name,
            'entry': cfg['entry'],
            'uuid': client['id'],
            'flow': client.get('flow', 'xtls-rprx-vision'),
            'server_name': server_name,
            'public_key': public_key,
            'short_id': short_id,
        })
    if not profiles:
        return None
    selector_name = '节点选择'
    lines = [
        'mixed-port: 7890',
        'allow-lan: false',
        'mode: rule',
        'log-level: info',
        'ipv6: true',
        'unified-delay: true',
        'tcp-concurrent: true',
        'global-client-fingerprint: chrome',
        '',
        'proxies:',
    ]
    for profile in profiles:
        lines.extend([
            '  - name: ' + yaml_string(profile['name']),
            '    type: vless',
            '    server: ' + yaml_string(PUBLIC_HOST),
            '    port: ' + str(profile['entry']),
            '    uuid: ' + yaml_string(profile['uuid']),
            '    network: tcp',
            '    tls: true',
            '    udp: true',
            '    flow: ' + yaml_string(profile['flow']),
            '    servername: ' + yaml_string(profile['server_name']),
            '    client-fingerprint: chrome',
            '    skip-cert-verify: false',
            '    reality-opts:',
            '      public-key: ' + yaml_string(profile['public_key']),
            '      short-id: ' + yaml_string(profile['short_id']),
            '',
        ])
    lines.extend([
        'proxy-groups:',
        '  - name: ' + yaml_string(selector_name),
        '    type: select',
        '    proxies:',
    ])
    lines.extend('      - ' + yaml_string(profile['name']) for profile in profiles)
    lines.extend(['', 'rules:', '  - MATCH,' + selector_name, ''])
    return ('\n'.join(lines)).encode('utf-8')


BOOT_JS = r'''try {
  document.documentElement.classList.toggle(
    'sidebar-pref-collapsed',
    localStorage.getItem('relay-sidebar-collapsed') === '1'
  );
} catch (_) {}'''


APP_JS = r'''(() => {
  const fetch = async (url, options = {}) => {
    const response = await window.fetch(url, {...options, signal: options.signal || AbortSignal.timeout(180000)});
    if (response.status === 401) throw new Error('登录已过期，请刷新页面重新登录');
    return response;
  };
  const shell = document.querySelector('.app-shell');
  const sidebarToggle = document.querySelector('[data-sidebar-toggle]');
  const setSidebarCollapsed = (collapsed) => {
    if (!shell || !sidebarToggle) return;
    shell.classList.toggle('sidebar-collapsed', collapsed);
    sidebarToggle.setAttribute('aria-expanded', String(!collapsed));
    sidebarToggle.setAttribute('aria-label', collapsed ? '展开侧边栏' : '收起侧边栏');
    sidebarToggle.title = collapsed ? '展开侧边栏' : '收起侧边栏';
  };
  try {
    setSidebarCollapsed(localStorage.getItem('relay-sidebar-collapsed') === '1');
  } catch (_) {
    setSidebarCollapsed(false);
  }
  if (shell) {
    shell.getBoundingClientRect();
    document.documentElement.classList.remove('sidebar-pref-collapsed');
    shell.classList.remove('sidebar-initializing');
  }
  const metricCells = (row) => ({
    latency: row.querySelector('[data-metric="latency"]'),
    speed: row.querySelector('[data-metric="speed"]'),
    purity: row.querySelector('[data-metric="purity"]'),
    status: row.querySelector('[data-metric="status"]'),
    checked: row.querySelector('[data-metric="checked"]')
  });
  const setLoading = (row) => {
    const spinner = document.createElement('span');
    spinner.className = 'spinner';
    spinner.setAttribute('aria-hidden', 'true');
    Object.values(metricCells(row)).forEach(cell => {
      if (!cell) return;
      cell.replaceChildren(spinner.cloneNode(true), document.createTextNode('检测中…'));
    });
  };
  const formatCheckedAt = (timestamp) => {
    if (!timestamp) return '—';
    const date = new Date(Number(timestamp) * 1000);
    if (Number.isNaN(date.getTime())) return '—';
    const pad = value => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  };
  const latencyElement = (value) => {
    const latency = Number(value);
    const element = document.createElement('span');
    if (!Number.isFinite(latency) || latency < 0) {
      element.textContent = '—';
      return element;
    }
    element.className = `latency ${latency <= 120 ? 'low' : (latency <= 200 ? 'medium' : 'high')}`;
    element.textContent = `${Math.round(latency)}ms`;
    return element;
  };
  const render = (row, result) => {
    const cells = metricCells(row);
    if (!result || result.error) {
      ['latency', 'speed', 'purity', 'checked'].forEach(name => { if (cells[name]) cells[name].textContent = '—'; });
      if (cells.status) {
        const badge = document.createElement('span');
        badge.className = 'status-badge bad';
        badge.textContent = '检测失败';
        const detail = document.createElement('span');
        detail.className = 'help';
        detail.textContent = ` · ${result && result.error ? result.error : '未返回检测结果'}`;
        cells.status.replaceChildren(badge, detail);
      }
      return;
    }
    if (cells.latency) cells.latency.replaceChildren(latencyElement(result.latency_ms));
    if (cells.speed) cells.speed.textContent = `${result.speed_mbps} Mbps`;
    if (cells.purity) cells.purity.textContent = result.purity || '未知';
    if (cells.checked) cells.checked.textContent = formatCheckedAt(result.checked_at);
    if (cells.status) {
      const badge = document.createElement('span');
      badge.className = 'status-badge ok';
      const dot = document.createElement('span');
      dot.className = 'online-dot';
      badge.append(dot, document.createTextNode('可用'));
      cells.status.replaceChildren(badge);
    }
  };
  const submit = async (form, rows) => {
    const button = form.querySelector('button');
    button.disabled = true;
    rows.forEach(setLoading);
    try {
      const body = new URLSearchParams(new FormData(form));
      const response = await fetch(form.action, {method: 'POST', body, headers: {'Accept': 'application/json'}});
      const data = await response.json();
      if (form.classList.contains('test-all-form')) {
        rows.forEach(row => render(row, (data.results && data.results[row.dataset.node]) || {error: data.error || '未返回检测结果'}));
      } else {
        render(rows[0], data.result || {error: data.error || '检测失败'});
      }
    } catch (error) {
      rows.forEach(row => render(row, {error: error.message}));
    } finally {
      button.disabled = false;
    }
  };
  const pagination = {page: 1, pageSize: 10};
  const renderNodePagination = () => {
    const rows = filterConsoleRows('.node-row', 'nodes');
    const summary = document.querySelector('[data-pagination-summary]');
    const pages = document.querySelector('[data-pagination-pages]');
    const previous = document.querySelector('[data-pagination-prev]');
    const next = document.querySelector('[data-pagination-next]');
    if (!summary || !pages || !previous || !next) return;
    const total = rows.length;
    const pageCount = Math.max(1, Math.ceil(total / pagination.pageSize));
    pagination.page = Math.min(Math.max(1, pagination.page), pageCount);
    const start = (pagination.page - 1) * pagination.pageSize;
    const end = Math.min(start + pagination.pageSize, total);
    rows.forEach((row, index) => { row.hidden = index < start || index >= end; });
    summary.textContent = total ? `显示 ${start + 1}-${end}，共 ${total} 个节点` : '暂无节点';
    previous.disabled = pagination.page <= 1;
    next.disabled = pagination.page >= pageCount;
    pages.replaceChildren(...Array.from({length: pageCount}, (_, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondary page-number' + (index + 1 === pagination.page ? ' active' : '');
      button.dataset.paginationPage = String(index + 1);
      button.textContent = String(index + 1);
      if (index + 1 === pagination.page) button.setAttribute('aria-current', 'page');
      button.hidden = index !== 0 && index !== pageCount - 1 && Math.abs(index + 1 - pagination.page) > 1;
      return button;
    }));
  };
  const forwardPagination = {page: 1, pageSize: 10};
  const renderForwardPagination = () => {
    const rows = filterConsoleRows('.forward-row', 'forward');
    const summary = document.querySelector('[data-forward-pagination-summary]');
    const pages = document.querySelector('[data-forward-pagination-pages]');
    const previous = document.querySelector('[data-forward-pagination-prev]');
    const next = document.querySelector('[data-forward-pagination-next]');
    if (!summary || !pages || !previous || !next) return;
    const total = rows.length;
    const pageCount = Math.max(1, Math.ceil(total / forwardPagination.pageSize));
    forwardPagination.page = Math.min(Math.max(1, forwardPagination.page), pageCount);
    const start = (forwardPagination.page - 1) * forwardPagination.pageSize;
    const end = Math.min(start + forwardPagination.pageSize, total);
    rows.forEach((row, index) => { row.hidden = index < start || index >= end; });
    summary.textContent = total ? `显示 ${start + 1}-${end}，共 ${total} 条转发` : '暂无转发';
    previous.disabled = forwardPagination.page <= 1;
    next.disabled = forwardPagination.page >= pageCount;
    pages.replaceChildren(...Array.from({length: pageCount}, (_, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondary page-number' + (index + 1 === forwardPagination.page ? ' active' : '');
      button.dataset.forwardPaginationPage = String(index + 1);
      button.textContent = String(index + 1);
      if (index + 1 === forwardPagination.page) button.setAttribute('aria-current', 'page');
      button.hidden = index !== 0 && index !== pageCount - 1 && Math.abs(index + 1 - forwardPagination.page) > 1;
      return button;
    }));
  };
  /* DELETE_DIALOG */
  const waitForReconnect = async () => {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      await new Promise(resolve => window.setTimeout(resolve, 1000));
      try {
        const response = await fetch('/healthz', {cache: 'no-store', credentials: 'same-origin'});
        if (response.ok) return true;
      } catch (_) {}
    }
    return false;
  };


  const submitMutation = async (form) => {
    const fastClientError = prepareFastClientSubscription(form);
    if (fastClientError) {
      const errorBox = form.querySelector('.form-error');
      if (errorBox) {
        errorBox.textContent = fastClientError;
        errorBox.hidden = false;
        errorBox.focus();
      }
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    const errorBox = form.querySelector('.form-error');
    const originalButtonText = button ? button.textContent : '';
    if (button) button.textContent = '保存中…';
    if (button) button.disabled = true;
    if (errorBox) {
      errorBox.hidden = true;
      errorBox.textContent = '';
    }
    const reloadAtRequestedView = () => {
      const currentPath = window.location.pathname;
      const returnPath = form.dataset.returnPath || (['/nodes', '/forward', '/host'].includes(currentPath) ? currentPath : '/nodes');
      window.location.replace(returnPath);
    };
    try {
      const response = await fetch(form.action, {
        method: 'POST',
        body: new URLSearchParams(new FormData(form)),
        headers: {'Accept': 'application/json'},
        credentials: 'same-origin'
      });
      let data = {};
      try {
        data = await response.json();
      } catch (_) {
        const invalid = new Error(`服务器返回了无效响应（HTTP ${response.status}）`);
        invalid.recoverable = true;
        throw invalid;
      }
      if (!response.ok || !data.ok) throw new Error(data.error || `操作失败（HTTP ${response.status}）`);
      if (form.action.endsWith('/forward/create') && data.forward) {
        closeModal(form.closest('.modal'));
        showForwardQr(data.forward, button, true);
        return;
      }
      if (data.metadata_only && form.closest('#edit-node-modal')) {
        reloadAtRequestedView();
        return;
      }
      reloadAtRequestedView();
    } catch (error) {
      if (error instanceof TypeError || error.recoverable) {
        if (errorBox) {
          errorBox.textContent = '入口服务正在重启，连接暂时中断，正在自动确认保存结果…';
          errorBox.hidden = false;
        }
        if (await waitForReconnect()) {
          reloadAtRequestedView();
          return;
        }
        error = new Error('服务器连接在保存时中断，30 秒内未恢复。请刷新页面确认结果。');
      }
      if (errorBox) {
        errorBox.textContent = error.message;
        errorBox.hidden = false;
        errorBox.focus();
      } else {
        consoleToast(error.message);
      }
      if (button) button.disabled = false;
    } finally {
      if (button && button.isConnected) {
        button.disabled = form.dataset.nodeValid === '0';
        button.textContent = originalButtonText;
      }
    }
  };
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (form.classList.contains('confirm-logout-form')) {
      event.preventDefault();
      const modal = document.getElementById('logout-confirm-modal');
      if (modal) openModal(modal, form.querySelector('button'));
    } else if (form.classList.contains('confirm-delete-form')) {
      event.preventDefault();
      openDeleteDialog(form, false);
    } else if (form.classList.contains('console-delete-confirm-form')) {
      event.preventDefault();
      confirmConsoleDelete();
    } else if (form.classList.contains('confirm-rotate-form') && !window.confirm('轮换后旧订阅链接会立即失效，确定继续吗？')) {
      event.preventDefault();
    } else if (form.classList.contains('node-delete-form')) {
      event.preventDefault();
      openDeleteDialog(form, true);
    } else if (form.classList.contains('node-test-form')) {
      event.preventDefault();
      const row = document.querySelector(`.node-row[data-node="${CSS.escape(form.dataset.node)}"]`);
      if (row) submit(form, [row]);
    } else if (form.classList.contains('test-all-form')) {
      event.preventDefault();
      submit(form, [...document.querySelectorAll('.node-row')]);
    } else if (form.classList.contains('async-form')) {
      event.preventDefault();
      submitMutation(form);
    }
  });
  let modalOpener = null;
  const setModalIsolation = (modal, isolated) => {
    document.querySelectorAll('.sidebar, .workspace > :not(.modal)').forEach(item => {
      if (isolated && !item.contains(modal)) item.setAttribute('inert', '');
      else item.removeAttribute('inert');
    });
  };
  const openModal = (modal, opener) => {
    if (!modal) return;
    modalOpener = opener || document.activeElement;
    modal.hidden = false;
    document.body.classList.add('modal-open');
    setModalIsolation(modal, true);
    if (modal.id === 'add-node-modal' || modal.id === 'edit-node-modal') updateExpiryDate(modal.querySelector('form'));
    if (modal.id === 'create-forward-modal') updateConditionalFields();
    const first = modal.querySelector('input:not([type="hidden"]):not([disabled]), select:not([disabled]), button');
    if (first) first.focus();
  };
  const closeModal = (modal) => {
    if (!modal || modal.dataset.busy === '1') return;
    const reloadAfterClose = modal.dataset.reloadAfterClose === '1';
    modal.hidden = true;
    document.body.classList.remove('modal-open');
    setModalIsolation(modal, false);
    if (modalOpener && modalOpener.isConnected) modalOpener.focus();
    modalOpener = null;
    if (reloadAfterClose) {
      delete modal.dataset.reloadAfterClose;
      window.location.replace('/forward');
    }
  };
  const activateView = (id, button) => {
    document.querySelectorAll('.view').forEach(view => { view.hidden = view.id !== id; });
    document.querySelectorAll('[data-view-target]').forEach(item => {
      const active = item === button;
      item.classList.toggle('active', active);
      if (active) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
    document.querySelectorAll('.modal:not([hidden])').forEach(closeModal);
    window.scrollTo({top: 0, behavior: 'smooth'});
  };
  const refreshHost = async (button) => {
    const original = button.textContent;
    button.disabled = true;
    button.textContent = '检测中…';
    try {
      const response = await fetch('/host/status', {headers: {'Accept': 'application/json'}});
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || '状态读取失败');
      const setField = (name, value) => document.querySelectorAll(`[data-host-field="${name}"]`).forEach(item => { item.textContent = value; });
      setField('hostname', data.hostname || '—');
      setField('uptime_text', data.uptime_text || '—');
      setField('load1', data.load1 || '—');
      setField('disk_used_percent', data.disk_used_percent == null ? '—' : `${data.disk_used_percent}%`);
      setField('public_ip', data.public_ip || '—');
      setField('os_name', data.os_name || '—');
      setField('cpu_text', data.cpu_text || '—');
      setField('memory_text', data.memory_text || '—');
      setField('disk_text', data.disk_text || '—');
      setField('kernel', data.kernel || '—');
      let healthy = Object.keys(data.services || {}).length > 0;
      Object.entries(data.services || {}).forEach(([key, service]) => {
        const row = document.querySelector(`[data-service="${CSS.escape(key)}"]`);
        const isActive = service.active === 'active';
        healthy = healthy && isActive;
        if (!row) return;
        const active = row.querySelector('[data-service-active]');
        const enabled = row.querySelector('[data-service-enabled]');
        if (active) {
          const dot = active.querySelector('.online-dot') || document.createElement('span');
          dot.className = 'online-dot';
          active.classList.toggle('ok', isActive);
          active.classList.toggle('bad', !isActive);
          active.replaceChildren(dot, document.createTextNode(isActive ? '运行中' : (service.active || '未知')));
        }
        if (enabled) enabled.textContent = service.enabled === 'enabled' ? '开机启用' : (service.enabled || '未知');
      });
      const checked = document.querySelector('[data-host-field="checked_label"]');
      if (checked) {
        checked.textContent = healthy ? '全部正常' : '发现故障';
        checked.classList.toggle('ok', healthy);
        checked.classList.toggle('bad', !healthy);
      }
    } catch (error) {
      button.textContent = '检测失败';
      window.setTimeout(() => { button.textContent = original; }, 1800);
    } finally {
      button.disabled = false;
      if (button.textContent === '检测中…') button.textContent = original;
    }
  };
  document.addEventListener('click', (event) => {
    const toggle = event.target.closest('[data-sidebar-toggle]');
    if (toggle) {
      const collapsed = !shell.classList.contains('sidebar-collapsed');
      setSidebarCollapsed(collapsed);
      try {
        localStorage.setItem('relay-sidebar-collapsed', collapsed ? '1' : '0');
      } catch (_) {}
      return;
    }
    const nav = event.target.closest('[data-view-target]');
    if (nav) {
      const viewUrl = nav.dataset.viewUrl;
      if (viewUrl && window.location.pathname !== viewUrl) history.pushState({}, '', viewUrl);
      activateView(nav.dataset.viewTarget, nav);
      return;
    }
    const copyButton = event.target.closest('[data-copy-value]');
    if (copyButton) {
      const value = copyButton.dataset.copyValue || '';
      const original = copyButton.dataset.copyLabel || copyButton.textContent;
      const copied = () => {
        copyButton.dataset.copyLabel = original;
        copyButton.textContent = '已复制';
        copyButton.classList.add('copied');
        window.setTimeout(() => {
          if (!copyButton.isConnected) return;
          copyButton.textContent = original;
          copyButton.classList.remove('copied');
        }, 1500);
      };
      const fallback = () => {
        const visibleField = copyButton.closest('.qr-result')?.querySelector('[data-forward-result-value]');
        const field = visibleField && visibleField.tagName === 'TEXTAREA' ? visibleField : document.createElement('textarea');
        const temporary = field !== visibleField;
        if (temporary) {
          field.value = value;
          field.setAttribute('readonly', '');
          field.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
          document.body.appendChild(field);
        }
        field.focus();
        field.select();
        field.setSelectionRange(0, field.value.length);
        const copiedByCommand = document.execCommand('copy');
        if (temporary) field.remove();
        if (copiedByCommand) {
          copied();
        } else if (!temporary) {
          copyButton.textContent = '已选中，请复制';
          window.setTimeout(() => {
            if (copyButton.isConnected) copyButton.textContent = original;
          }, 2200);
        } else {
          copyButton.textContent = '复制失败';
          window.setTimeout(() => {
            if (copyButton.isConnected) copyButton.textContent = original;
          }, 2200);
        }
      };
      if (navigator.clipboard?.writeText) navigator.clipboard.writeText(value).then(copied).catch(fallback);
      else fallback();
      return;
    }
    const mixedForward = event.target.closest('[data-mixed-forward-nodes]');
    if (mixedForward) { showMixedForwardNodes(mixedForward); return; }
    const qrButton = event.target.closest('[data-qr-forward]');
    if (qrButton) {
      showForwardQr({
        id: qrButton.dataset.qrForward,
        label: qrButton.dataset.qrLabel || '链接',
        value: qrButton.dataset.qrValue || ''
      }, qrButton);
      return;
    }
    const hostButton = event.target.closest('[data-host-refresh]');
    if (hostButton) {
      refreshHost(hostButton);
      return;
    }
    const forwardPageButton = event.target.closest('[data-forward-pagination-page]');
    if (forwardPageButton) {
      forwardPagination.page = Number(forwardPageButton.dataset.forwardPaginationPage) || 1;
      renderForwardPagination();
      return;
    }
    const forwardPrevious = event.target.closest('[data-forward-pagination-prev]');
    if (forwardPrevious) {
      forwardPagination.page -= 1;
      renderForwardPagination();
      return;
    }
    const forwardNext = event.target.closest('[data-forward-pagination-next]');
    if (forwardNext) {
      forwardPagination.page += 1;
      renderForwardPagination();
      return;
    }
    const pageButton = event.target.closest('[data-pagination-page]');
    if (pageButton) {
      pagination.page = Number(pageButton.dataset.paginationPage) || 1;
      renderNodePagination();
      return;
    }
    const previous = event.target.closest('[data-pagination-prev]');
    if (previous) {
      pagination.page -= 1;
      renderNodePagination();
      return;
    }
    const next = event.target.closest('[data-pagination-next]');
    if (next) {
      pagination.page += 1;
      renderNodePagination();
      return;
    }
    const subscriptionUser = event.target.closest('[data-subscription-user-select]');
    if (subscriptionUser) { selectSubscriptionUser(subscriptionUser.closest('#create-forward-modal'), subscriptionUser.dataset.subscriptionUserSelect); return; }
    const opener = event.target.closest('[data-modal-open]');
    if (opener) {
      const modal = document.getElementById(opener.dataset.modalOpen);
      if (modal) {
        if (opener.dataset.forwardId) {
          const idField = modal.querySelector('[name="id"]');
          const titleField = modal.querySelector('[name="title"]');
          if (idField) idField.value = opener.dataset.forwardId || '';
          if (titleField) titleField.value = opener.dataset.forwardTitle || '';
        }
        if (opener.dataset.editTag) {
          modal.dataset.countryEdited = '';
          const values = {
            config: opener.dataset.editConfig || '',
            tag: opener.dataset.editTag || '',
            user: opener.dataset.editUser || '',
            country: opener.dataset.editCountry || '',
            activated_on: opener.dataset.editActivatedOn || '',
            duration_days: opener.dataset.editDurationDays || '',
            expires_on: opener.dataset.editExpiresOn || ''
          };
          Object.entries(values).forEach(([name, value]) => {
            const field = modal.querySelector(`[name="${name}"], #edit-${name}`);
            if (field) field.value = value;
          });
        }
        openModal(modal, opener);
      }
      return;
    }
    const closer = event.target.closest('[data-modal-close]');
    if (closer) {
      closeModal(closer.closest('.modal'));
      return;
    }
    if (event.target.classList.contains('modal-backdrop')) {
      closeModal(event.target.closest('.modal'));
    }
  });
  const updateConditionalFields = () => {
    const protocol = document.querySelector('#add-node-modal [name="protocol"]')?.value;
    document.querySelectorAll('[data-protocol-fields]').forEach(group => {
      group.hidden = group.dataset.protocolFields === 'vless' ? protocol !== 'vless' : protocol === 'vless';
    });
    const modal = document.querySelector('#create-forward-modal');
    const mode = modal?.querySelector('[name="mode"]:checked')?.value;
    const isFastClient = mode === 'subscription';
    const form = modal?.querySelector('form');
    if (form) form.classList.toggle('fastclient-mode', isFastClient);
    const subscription = modal?.querySelector('[data-forward-subscription]');
    const upstreamField = modal?.querySelector('[data-forward-upstream]');
    const searchField = modal?.querySelector('.forward-search-field');
    const labelCaption = modal?.querySelector('[data-forward-label]');
    const labelInput = modal?.querySelector('[name="label"]');
    if (subscription) subscription.hidden = !isFastClient;
    if (upstreamField) upstreamField.hidden = isFastClient;
    if (searchField) searchField.hidden = !isFastClient;
    if (labelCaption) labelCaption.textContent = isFastClient ? '订阅名称' : '转发名称';
    if (labelInput) labelInput.placeholder = isFastClient ? '例如：客户 A 专属订阅' : '例如：台湾住宅出口';
    subscription?.querySelectorAll('[data-subscription-node]').forEach(box => {
      const name = box.closest('.subscription-node-card')?.querySelector('[data-subscription-node-label]');
      if (name) name.disabled = !box.checked;
    });
    const help = modal?.querySelector('[data-forward-help]');
    if (help) help.textContent = mode === 'socks'
      ? '选择上游节点；系统会分配公网端口和独立账号密码。'
      : isFastClient
        ? 'FastClient 订阅可包含多个独立节点，客户端会在同一订阅中显示全部自定义名称。'
        : '选择要转发的上游节点，并复用既有 VLESS Reality 入口。';
  };
  const selectSubscriptionUser = (modal, userId) => {
    if (!modal || !userId) return;
    modal.querySelectorAll('[data-subscription-user-select]').forEach(button => button.classList.toggle('active', button.dataset.subscriptionUserSelect === userId));
    modal.querySelectorAll('.subscription-node-card[data-subscription-user]').forEach(card => card.hidden = card.dataset.subscriptionUser !== userId);
  };
  const filterSubscriptionUsers = (modal, query) => {
    if (!modal) return;
    const normalized = (query || '').trim().toLocaleLowerCase();
    const buttons = [...modal.querySelectorAll('[data-subscription-user-select]')];
    buttons.forEach(button => button.hidden = Boolean(normalized) && !((button.dataset.subscriptionSearch || '').toLocaleLowerCase().includes(normalized)));
    const active = buttons.find(button => button.classList.contains('active') && !button.hidden);
    const first = buttons.find(button => !button.hidden);
    if (!active && first) selectSubscriptionUser(modal, first.dataset.subscriptionUserSelect);
  };
  const filterSubscriptionNodes = (modal, query) => {
    if (!modal) return;
    const normalized = (query || '').trim().toLocaleLowerCase();
    modal.querySelectorAll('.subscription-node-card[data-subscription-user]').forEach(card => {
      card.hidden = Boolean(normalized) && !card.textContent.toLocaleLowerCase().includes(normalized);
    });
  };
  const showMixedForwardNodes = (opener) => {
    const modal = document.getElementById('mixed-forward-nodes-modal');
    if (!modal) return;
    let nodes = [];
    try { nodes = JSON.parse(opener.dataset.mixedForwardNodes || '[]'); } catch (_) {}
    const list = modal.querySelector('[data-mixed-forward-node-list]');
    if (list) {
      list.replaceChildren(...nodes.map((node, index) => {
        const item = document.createElement('div'); item.className = 'mixed-forward-node';
        const title = document.createElement('b'); title.textContent = node.label || `节点 ${index + 1}`;
        const detail = document.createElement('span'); detail.textContent = `${node.address || '—'} · ${node.country || '—'} · 用户：${node.user || '未填写'}`;
        item.append(title, detail); return item;
      }));
    }
    const count = modal.querySelector('[data-mixed-forward-count]');
    if (count) count.textContent = `共 ${nodes.length} 个节点`;
    openModal(modal, opener);
  };
  const showForwardQr = (forward, opener, reloadAfterClose = false) => {
    const modal = document.querySelector('#forward-result-modal');
    if (!modal || !forward?.id || !forward?.value) return;
    modal.querySelector('[data-forward-result-label]').textContent = forward.label || '新建链接';
    modal.querySelector('[data-forward-result-value]').value = forward.value;
    const copy = modal.querySelector('[data-copy-value]');
    copy.dataset.copyValue = forward.value;
    copy.dataset.copyLabel = '复制链接';
    copy.textContent = '复制链接';
    const image = modal.querySelector('[data-forward-qr-image]');
    image.src = `/forward/qr?id=${encodeURIComponent(forward.id)}`;
    image.alt = `${forward.label || '链接'}二维码`;
    if (reloadAfterClose) modal.dataset.reloadAfterClose = '1';
    else delete modal.dataset.reloadAfterClose;
    openModal(modal, opener);
  };
  const prepareFastClientSubscription = (form) => {
    if (!form.matches('#create-forward-modal form') || form.querySelector('[name="mode"]:checked')?.value !== 'subscription') return '';
    const target = form.querySelector('[name="subscription_nodes"]');
    const entries = [...form.querySelectorAll('[data-subscription-node]:checked')].map(box => ({
      upstream: box.value,
      label: box.closest('.subscription-node-card')?.querySelector('[data-subscription-node-label]')?.value.trim() || ''
    }));
    if (!entries.length) return '请至少选择一个 FastClient 订阅节点。';
    if (entries.some(entry => !entry.label)) return '请为每个已选节点填写客户端显示名称。';
    const labels = entries.map(entry => entry.label.toLocaleLowerCase());
    if (new Set(labels).size !== labels.length) return '同一订阅内的客户端显示名称不能重复。';
    if (target) target.value = JSON.stringify(entries);
    return '';
  };
  const updateExpiryDate = (form) => {
    const opened = form.querySelector('[name="activated_on"]');
    const duration = form.querySelector('[name="duration_days"]');
    const expires = form.querySelector('[name="expires_on"]');
    if (!opened || !duration || !expires) return;
    const days = Number(duration.value);
    if (!opened.value || !Number.isInteger(days) || days < 1) {
      expires.value = '';
      return;
    }
    const value = new Date(`${opened.value}T00:00:00`);
    if (Number.isNaN(value.getTime())) {
      expires.value = '';
      return;
    }
    value.setDate(value.getDate() + days);
    const pad = part => String(part).padStart(2, '0');
    expires.value = `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
  };
  let nodePreviewTimer = 0;
  let nodePreviewRequest = 0;
  const previewNodeInput = async (form) => {
    const input = form.querySelector('[name="node_input"]');
    const status = form.querySelector('[data-node-parse-status]');
    if (!input || !status) return;
    const submit = form.querySelector('button[type="submit"]');
    const isEdit = Boolean(form.closest('#edit-node-modal'));
    if (!input.value.trim()) {
      nodePreviewRequest += 1;
      form.dataset.nodeValid = isEdit ? '' : '0';
      if (submit) submit.disabled = !isEdit;
      status.textContent = isEdit ? '留空将保留当前上游数据；粘贴新链接后会自动识别、检测并在保存时更新。' : '粘贴后自动识别；SOCKS5、HTTP、VLESS Reality 均可导入。';
      return;
    }
    const request = ++nodePreviewRequest;
    form.dataset.nodeValid = '0';
    if (submit) submit.disabled = true;
    status.textContent = '已识别节点数据，正在检测连通性与延迟…';
    try {
      const body = new URLSearchParams();
      body.set('csrf', form.querySelector('[name="csrf"]')?.value || '');
      body.set('node_input', input.value);
      const response = await fetch('/node/validate', {method: 'POST', body, headers: {'Accept': 'application/json'}, credentials: 'same-origin'});
      const data = await response.json();
      if (request !== nodePreviewRequest) return;
      if (!response.ok || !data.ok) throw new Error(data.error || '未识别到可用节点');
      const labels = {socks: 'SOCKS5', http: 'HTTP', vless: 'VLESS Reality'};
      const country = data.country ? ` · 国家/地区：${data.country}` : ' · 国家/地区暂未识别';
      if (!data.valid) {
        status.textContent = `已识别 ${labels[data.protocol] || data.protocol}：${data.address}:${data.port}${country} · 检测失败：${data.error || '无法通过该节点访问网络'}`;
        return;
      }
      const countryField = form.querySelector('[name="country"]');
      if (countryField && data.country && form.dataset.countryEdited !== '1') countryField.value = data.country;
      form.dataset.nodeValid = '1';
      if (submit) submit.disabled = false;
      status.replaceChildren(
        document.createTextNode(`检测通过 · ${labels[data.protocol] || data.protocol}：${data.address}:${data.port}${country} · 延迟：`),
        latencyElement(data.latency_ms)
      );
    } catch (error) {
      if (request !== nodePreviewRequest) return;
      status.textContent = `自动识别失败：${error.message}`;
    }
  };
  const queueNodePreview = (form) => {
    window.clearTimeout(nodePreviewTimer);
    nodePreviewTimer = window.setTimeout(() => previewNodeInput(form), 350);
  };
  document.addEventListener('change', event => {
    if (event.target.matches('#add-node-modal [name="protocol"], #create-forward-modal [name="mode"]')) updateConditionalFields();
    if (event.target.matches('[data-subscription-node]')) updateConditionalFields();
    if (event.target.matches('#add-node-modal [name="activated_on"], #add-node-modal [name="duration_days"], #edit-node-modal [name="activated_on"], #edit-node-modal [name="duration_days"]')) updateExpiryDate(event.target.closest('form'));
  });
  document.addEventListener('input', event => {
    if (event.target.matches('#add-node-modal [name="activated_on"], #add-node-modal [name="duration_days"], #edit-node-modal [name="activated_on"], #edit-node-modal [name="duration_days"]')) updateExpiryDate(event.target.closest('form'));
    if (event.target.matches('#add-node-modal [name="node_input"], #edit-node-modal [name="node_input"]')) queueNodePreview(event.target.closest('form'));
    if (event.target.matches('#edit-node-modal [name="country"]')) event.target.closest('form').dataset.countryEdited = '1';
    if (event.target.matches('[data-subscription-node-search]')) filterSubscriptionNodes(event.target.closest('#create-forward-modal'), event.target.value);
  });
  document.querySelectorAll('label:not([for])').forEach((label, index) => {
    if (label.querySelector('input,select,textarea')) return;
    const field = label.nextElementSibling;
    if (!field || !field.matches('input,select,textarea')) return;
    if (!field.id) field.id = `field-${index}`;
    label.htmlFor = field.id;
  });
  document.querySelector('[data-view-target].active')?.setAttribute('aria-current', 'page');
  document.addEventListener('keydown', (event) => {
    const modal = document.querySelector('.modal:not([hidden])');
    if (event.key === 'Escape' && modal) {
      closeModal(modal);
      return;
    }
    if (event.key === 'Tab' && modal) {
      const focusable = [...modal.querySelectorAll('button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled])')];
      if (!focusable.length) return;
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });
  /* CONSOLE_EXTENSION */
  updateConditionalFields();
  renderNodePagination();
  renderForwardPagination();
  const viewByPath = {'/nodes': 'nodes-view', '/forward': 'forward-view', '/host': 'host-view'};
  const activatePathView = () => {
    const requestedView = viewByPath[window.location.pathname] || 'nodes-view';
    const requestedButton = document.querySelector(`[data-view-target="${requestedView}"]`);
    if (requestedButton) activateView(requestedView, requestedButton);
  };
  window.addEventListener('popstate', activatePathView);
  activatePathView();
})();'''


HTML_HEAD = '''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<script src="/boot.js"></script>
<style>
:root{
  --bg:#f5f5f7;
  --surface:#fff;
  --surface-raised:#fff;
  --soft:#f5f5f7;
  --soft-hover:#ececf0;
  --line:#d2d2d7;
  --line-soft:#e5e5e7;
  --text:#1d1d1f;
  --muted:#6e6e73;
  --blue:#0071e3;
  --blue-pressed:#0066cc;
  --blue-soft:#eaf2ff;
  --green:#248a3d;
  --green-soft:#edf7ee;
  --red:#d70015;
  --red-soft:#fff1f0;
  --radius-lg:18px;
  --radius-md:14px;
  --radius-sm:10px;
  --shadow:0 10px 28px rgba(0,0,0,.05);
}

*{box-sizing:border-box}
html{background:var(--bg)}
body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased;
}
body.modal-open{overflow:hidden}
main{width:100%;min-height:100vh}
h1,h2,h3,p{margin-top:0}
h1{font-size:28px;letter-spacing:-.7px}
h2{font-size:22px;letter-spacing:-.4px}
h3{font-size:16px}
.muted,.help{color:var(--muted)}
.help{font-size:12px}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}

/* Application frame */
.app-shell{
  min-height:100vh;
  display:grid;
  grid-template-columns:240px minmax(0,1fr);
  transition:grid-template-columns .2s ease;
}
.app-shell.sidebar-collapsed{grid-template-columns:76px minmax(0,1fr)}
.app-shell.sidebar-initializing,
.app-shell.sidebar-initializing *{transition:none!important}
.sidebar{
  position:sticky;
  top:0;
  height:100vh;
  overflow-y:auto;
  display:flex;
  flex-direction:column;
  padding:24px 16px 18px;
  background:var(--surface);
  border-right:1px solid var(--line);
  transition:padding .2s ease;
}
.brand{
  display:flex;
  align-items:center;
  gap:11px;
  padding:3px 4px 24px 8px;
  border-bottom:1px solid var(--line-soft);
}
.brand-copy{min-width:0;flex:1}
.sidebar-toggle{
  width:30px;
  height:30px;
  flex:none;
  display:grid;
  place-items:center;
  padding:0;
  border:1px solid var(--line);
  border-radius:9px;
  background:var(--surface);
  color:var(--muted);
}
.sidebar-toggle:hover{background:var(--soft);color:var(--text)}
.sidebar-toggle svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;transition:transform .2s ease}
.brand-mark,.login-mark{
  display:grid;
  place-items:center;
  background:var(--blue);
  color:#fff;
  font-weight:700;
}
.brand-mark{width:36px;height:36px;border-radius:11px;font-size:18px}
.brand b{display:block;font-size:17px;letter-spacing:-.2px}
.brand span{display:block;margin-top:2px;color:var(--muted);font-size:11px}
.side-nav{display:grid;gap:7px;padding-top:18px}
.nav-item{
  width:100%;
  display:flex;
  align-items:center;
  gap:11px;
  padding:11px 12px;
  border:1px solid transparent;
  border-radius:11px;
  background:transparent;
  color:var(--muted);
  text-align:left;
  font-weight:600;
}
.nav-item:hover{background:var(--soft);color:var(--text)}
.nav-item.active{background:var(--blue-soft);border-color:#d5e5ff;color:var(--blue)}
.nav-icon{width:19px;flex:none;text-align:center;font-size:19px;line-height:1}
.nav-icon svg,.service-icon svg{
  display:block;
  width:19px;
  height:19px;
  fill:none;
  stroke:currentColor;
  stroke-width:1.8;
  stroke-linecap:round;
  stroke-linejoin:round;
}
.sidebar-bottom{margin-top:auto;padding-top:18px;border-top:1px solid var(--line-soft)}
.sidebar-host{display:flex;align-items:center;gap:9px;padding:9px 8px 12px}
.sidebar-host b,.sidebar-host span{display:block}
.sidebar-host b{font-size:12px}
.sidebar-host div span{margin-top:2px;color:var(--muted);font-size:11px}
.logout-button{width:100%}
.app-shell.sidebar-collapsed .logout-button{padding-inline:4px;font-size:11px}
.app-shell.sidebar-collapsed .sidebar{padding-inline:12px}
.app-shell.sidebar-collapsed .brand{justify-content:center;padding-inline:0}
.app-shell.sidebar-collapsed .brand-mark,
.app-shell.sidebar-collapsed .brand-copy,
.app-shell.sidebar-collapsed .nav-label,
.app-shell.sidebar-collapsed .sidebar-host div{display:none}
.app-shell.sidebar-collapsed .sidebar-toggle svg{transform:rotate(180deg)}
.app-shell.sidebar-collapsed .nav-item{justify-content:center;gap:0;padding-inline:0}
.app-shell.sidebar-collapsed .sidebar-host{justify-content:center;padding-inline:0}
@media(min-width:921px){
  html.sidebar-pref-collapsed .app-shell{grid-template-columns:76px minmax(0,1fr)}
  html.sidebar-pref-collapsed .app-shell .logout-button{padding-inline:4px;font-size:11px}
  html.sidebar-pref-collapsed .app-shell .sidebar{padding-inline:12px}
  html.sidebar-pref-collapsed .app-shell .brand{justify-content:center;padding-inline:0}
  html.sidebar-pref-collapsed .app-shell .brand-mark,
  html.sidebar-pref-collapsed .app-shell .brand-copy,
  html.sidebar-pref-collapsed .app-shell .nav-label,
  html.sidebar-pref-collapsed .app-shell .sidebar-host div{display:none}
  html.sidebar-pref-collapsed .app-shell .sidebar-toggle svg{transform:rotate(180deg)}
  html.sidebar-pref-collapsed .app-shell .nav-item{justify-content:center;gap:0;padding-inline:0}
  html.sidebar-pref-collapsed .app-shell .sidebar-host{justify-content:center;padding-inline:0}
}
.workspace{
  min-width:0;
  min-height:100vh;
  display:flex;
  flex-direction:column;
  padding:24px 28px 28px;
}
.view{width:100%;max-width:none;margin:0}
.view[hidden]{display:none}
.nodes-view{min-height:0;display:flex;flex:1;flex-direction:column}
.view-heading{
  min-height:42px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:20px;
  margin-bottom:14px;
}
.view-heading h2{margin:0}
.section-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}

/* Surfaces and status */
.card,.panel{
  background:var(--surface-raised);
  border:1px solid var(--line);
  box-shadow:var(--shadow);
}
.card{padding:18px;border-radius:var(--radius-lg)}
.panel{padding:16px;border-radius:var(--radius-md)}
.summary-strip,.host-summary{
  display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));
  gap:12px;
  margin:0 0 14px;
}
.summary-strip>div,.host-stat{
  min-width:0;
  padding:15px 17px;
  background:var(--surface);
  border:1px solid var(--line);
  border-radius:var(--radius-md);
  box-shadow:0 3px 12px rgba(0,0,0,.025);
}
.summary-strip span,.host-stat span{display:block;color:var(--muted);font-size:12px}
.summary-strip b,.host-stat b{
  display:block;
  margin-top:6px;
  overflow-wrap:anywhere;
  font-size:20px;
  line-height:1.25;
  letter-spacing:-.4px;
}
.host-stat b{font-size:18px}
.online-dot{display:inline-block;width:7px;height:7px;flex:none;border-radius:50%;background:var(--green)}
.status-badge{
  display:inline-flex;
  align-items:center;
  gap:6px;
  padding:5px 9px;
  border-radius:999px;
  background:var(--soft);
  font-size:12px;
  white-space:nowrap;
}
.status-badge.ok{background:var(--green-soft);color:var(--green)}
.status-badge.bad{background:var(--red-soft);color:var(--red)}
.status-badge.warn{background:#fff4ce;color:#8a5a00}
.status-badge.bad .online-dot{background:var(--red)}
.status-badge.neutral{color:var(--muted)}
.online-dot.offline{background:var(--red)}

/* Buttons and forms */
button{
  min-height:36px;
  padding:9px 14px;
  border:0;
  border-radius:var(--radius-sm);
  background:var(--blue);
  color:#fff;
  font:600 13px/1.25 inherit;
  cursor:pointer;
  transition:background-color .15s ease,border-color .15s ease,transform .15s ease;
}
button:hover{background:var(--blue-pressed)}
button:active:not(:disabled){transform:translateY(1px)}
button:disabled{opacity:.5;cursor:default}
button.secondary{border:1px solid var(--line);background:var(--surface);color:var(--text)}
button.secondary:hover{background:var(--soft)}
button.danger{border:1px solid #f0c7c3;background:var(--red-soft);color:var(--red)}
button.danger:hover{background:#ffe7e5}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{
  outline:3px solid rgba(0,113,227,.18);
  outline-offset:2px;
}
label{display:block;margin:11px 0 6px;font-size:12px;font-weight:600}
.form-error{margin:10px 0;padding:10px 12px;border:1px solid #f2c6c2;border-radius:10px;background:var(--red-soft);color:#b42318}
.form-error[hidden],[data-protocol-fields][hidden],[data-forward-socks][hidden]{display:none}
[data-forward-subscription][hidden],[data-forward-single][hidden]{display:none}
.subscription-node-list{display:grid;gap:8px;max-height:300px;overflow:auto;padding-right:2px}
.subscription-node-card{padding:10px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface)}
.subscription-node-check{display:flex;align-items:flex-start;gap:9px;margin:0;cursor:pointer}
.subscription-node-check input{width:auto;margin:3px 0 0}
.subscription-node-check b,.subscription-node-check small{display:block}
.subscription-node-check b{font-size:12px}
.subscription-node-check small{margin-top:3px;color:var(--muted);font-size:11px;font-weight:400}
.subscription-node-name{margin:8px 0 0;font-size:11px;color:var(--muted)}
.subscription-node-name input{margin-top:4px;padding:7px 9px;font-size:12px}
.subscription-node-name input:disabled{background:var(--soft);color:var(--muted);cursor:not-allowed}
#create-forward-modal .modal-panel{width:min(100%,1040px)}
#create-forward-modal .forward-primary,#create-forward-modal .forward-secondary{min-width:0}
#create-forward-modal form.fastclient-mode .forward-grid{grid-template-columns:minmax(0,1fr);gap:16px}
#create-forward-modal form.fastclient-mode .forward-primary{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,380px);gap:14px 20px;align-items:end}
#create-forward-modal form.fastclient-mode .subscription-composer{grid-column:1 / -1}
#create-forward-modal form.fastclient-mode .subscription-node-list{grid-template-columns:repeat(2,minmax(0,1fr));max-height:292px;padding:0}
#create-forward-modal form.fastclient-mode .subscription-node-card{height:100%;box-sizing:border-box}
#create-forward-modal form.fastclient-mode .forward-secondary{display:flex;align-items:center;justify-content:space-between;gap:18px;padding-top:2px;border-top:1px solid var(--line-soft)}
#create-forward-modal form.fastclient-mode .forward-secondary [data-forward-help]{max-width:600px;margin:0}
#create-forward-modal form.fastclient-mode .forward-secondary .actions{flex:none;margin:0}
.subscription-composer{min-width:0}
.subscription-composer-head{display:flex;align-items:end;justify-content:space-between;gap:16px;margin:0 0 8px}
.subscription-composer-head label{margin:0 0 3px}
.subscription-composer-head .help{margin:0}
.subscription-composer-tip{color:var(--muted);font-size:12px;white-space:nowrap}
@media(max-width:720px){
  #create-forward-modal form.fastclient-mode .forward-primary{grid-template-columns:1fr}
  #create-forward-modal form.fastclient-mode .subscription-node-list{grid-template-columns:1fr;max-height:260px}
  #create-forward-modal form.fastclient-mode .forward-secondary{align-items:flex-start;flex-direction:column}
  #create-forward-modal form.fastclient-mode .forward-secondary .actions{width:100%}
  .subscription-composer-head{align-items:flex-start;flex-direction:column;gap:3px}
}
.token-panel{margin-top:14px}
input,select,textarea{
  width:100%;
  padding:10px 11px;
  border:1px solid var(--line);
  border-radius:var(--radius-sm);
  outline:0;
  background:#fff;
  color:var(--text);
  font:inherit;
}
input:focus,select:focus,textarea:focus{border-color:var(--blue)}
textarea{min-height:60px;resize:vertical}
.field-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:18px}
.mode{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:8px;
  margin:0;
}
.mode label{
  min-height:40px;
  display:flex;
  align-items:center;
  justify-content:center;
  gap:6px;
  margin:0;
  padding:9px 10px;
  border:1px solid var(--line);
  border-radius:var(--radius-sm);
  background:var(--surface);
  font-weight:500;
  white-space:nowrap;
  cursor:pointer;
}
.mode label:has(input:checked){border-color:#9fc8f2;background:var(--blue-soft);color:var(--blue)}
.mode input{width:auto;margin:0}

/* Tables */
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:12px}
table{width:100%;min-width:720px;border-collapse:collapse}
th,td{
  padding:12px 14px;
  border-bottom:1px solid var(--line-soft);
  text-align:left;
  vertical-align:middle;
  font-size:13px;
}
th{background:var(--soft);color:var(--muted);font-weight:600}
tbody tr:last-child td{border-bottom:1px solid var(--line-soft)}
tbody tr:hover td{background:#fafafa}
.empty{padding:28px;color:var(--muted);text-align:center}
.kind{
  display:inline-block;
  padding:3px 7px;
  border-radius:6px;
  background:#1d4e89;
  color:#fff;
  font-size:11px;
  font-weight:700;
}
.kind.vless{background:#5e3bbd}
.row-actions{display:flex;align-items:center;justify-content:center;gap:6px;flex-wrap:nowrap}
.row-actions form{display:inline}
.row-actions button{min-height:32px;padding:7px 9px;white-space:nowrap;font-size:12px}
.metric{font-variant-numeric:tabular-nums;white-space:nowrap}
.latency{font-weight:700;font-variant-numeric:tabular-nums}
.latency.low{color:#16803a}
.latency.medium{color:#b45309}
.latency.high{color:#c8333f}
.checked{color:var(--muted);font-size:12px;white-space:nowrap}

/* Node inventory */
.nodes-panel{
  min-height:0;
  display:flex;
  flex:1;
  flex-direction:column;
  overflow:hidden;
  padding:0;
}
.nodes-panel .tablewrap{
  min-height:0;
  flex:1;
  border:0;
  border-radius:0;
  overflow:auto;
  scrollbar-width:thin;
  scrollbar-color:#b8c0cc transparent;
}
.nodes-panel table{width:100%;min-width:1220px;table-layout:auto;border-collapse:separate;border-spacing:0}
.nodes-panel th{
  position:sticky;
  top:0;
  z-index:2;
  padding:10px 8px;
  border-bottom:1px solid var(--line);
  line-height:1.25;
  white-space:normal;
}
.nodes-panel th,.nodes-panel td{
  padding:14px 16px;
  overflow:visible;
  text-align:center;
  text-overflow:clip;
  vertical-align:middle;
  white-space:nowrap;
}
.nodes-panel th:nth-child(1),.nodes-panel td:nth-child(1){width:150px;min-width:150px}
.nodes-panel th:nth-child(2),.nodes-panel td:nth-child(2){width:110px;min-width:110px}
.nodes-panel th:nth-child(3),.nodes-panel td:nth-child(3){width:170px;min-width:170px}
.nodes-panel th:nth-child(4),.nodes-panel td:nth-child(4){width:170px;min-width:170px}
.nodes-panel th:nth-child(5),.nodes-panel td:nth-child(5){width:100px;min-width:100px}
.nodes-panel th:nth-child(6),.nodes-panel td:nth-child(6){width:140px;min-width:140px}
.nodes-panel th:nth-child(7),.nodes-panel td:nth-child(7){width:110px;min-width:110px}
.nodes-panel th:nth-child(8),.nodes-panel td:nth-child(8){width:110px;min-width:110px}
.nodes-panel th:nth-child(9),.nodes-panel td:nth-child(9){
  position:sticky;
  right:0;
  width:190px;
  min-width:190px;
  background:var(--surface);
  box-shadow:-1px 0 0 var(--line-soft);
}
.nodes-panel th:nth-child(9){z-index:4;background:var(--soft)}
.nodes-panel tbody tr:hover td:nth-child(9){background:#fafafa}
.nodes-panel .status-cell{overflow:visible;text-overflow:clip}
.nodes-panel .status-cell .help{
  display:inline-block;
  max-width:120px;
  overflow:hidden;
  text-overflow:ellipsis;
  vertical-align:middle;
}
.table-pagination{
  min-height:52px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:12px;
  padding:9px 14px;
  border-top:0;
  background:var(--surface);
}
.pagination-controls,.pagination-pages{display:flex;align-items:center;gap:8px}
.pagination-controls button{min-width:34px;min-height:32px;padding:7px 10px}
.pagination-pages .page-number.active,
.pagination-pages .page-number.active:hover{border-color:var(--blue);background:var(--blue);color:#fff}

/* Forwarding and host views */
.form-panel{max-width:1100px}
.forward-grid{
  display:grid;
  grid-template-columns:minmax(280px,340px) minmax(420px,1fr);
  gap:28px;
  align-items:start;
}
/* Unified create-forward form: all output modes share one compact layout. */
#create-forward-modal .modal-panel{width:min(calc(100% - 32px),860px)}
#create-forward-modal .forward-grid{display:block}
#create-forward-modal .forward-primary{
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:14px 16px;
  align-items:end;
}
#create-forward-modal .forward-primary>div,#create-forward-modal .forward-primary>section{min-width:0}
#create-forward-modal .forward-upstream-field,
#create-forward-modal .forward-name-field,
#create-forward-modal .forward-mode-field,
#create-forward-modal .subscription-composer{grid-column:1 / -1}
#create-forward-modal .forward-primary label{margin:0 0 6px}
#create-forward-modal .forward-secondary{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:16px;
  margin-top:20px;
  padding-top:16px;
  border-top:1px solid var(--line-soft);
}
#create-forward-modal .forward-secondary .help{margin:0;max-width:520px}
#create-forward-modal .forward-secondary .actions{flex:none;margin:0}
#create-forward-modal form.fastclient-mode .forward-grid{display:block;gap:0}
#create-forward-modal form.fastclient-mode .forward-primary{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 16px;align-items:end}
#create-forward-modal form.fastclient-mode .subscription-composer{grid-column:1 / -1}
#create-forward-modal form.fastclient-mode .subscription-node-list{grid-template-columns:repeat(2,minmax(0,1fr));max-height:292px;padding:0}
#create-forward-modal form.fastclient-mode .forward-secondary{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:16px;border-top:1px solid var(--line-soft)}
#create-forward-modal .forward-grid>div{min-width:0}
/* SOCKS5/VLESS stay compact; FastClient expands only for its two-column node picker. */
#create-forward-modal .modal-panel{width:min(calc(100% - 32px),760px)}
#create-forward-modal:has(form.fastclient-mode) .modal-panel{width:min(calc(100% - 32px),920px)!important}
#create-forward-modal form.fastclient-mode .forward-primary{grid-template-columns:minmax(390px,1.1fr) minmax(300px,.9fr);gap:14px 18px;align-items:start}
#create-forward-modal form.fastclient-mode .subscription-composer{grid-column:1;grid-row:1 / span 5;align-self:start;display:flex;flex-direction:column}
#create-forward-modal form.fastclient-mode .forward-search-field,#create-forward-modal form.fastclient-mode .forward-name-field,#create-forward-modal form.fastclient-mode .forward-quota-field,#create-forward-modal form.fastclient-mode .forward-expire-field,#create-forward-modal form.fastclient-mode .forward-mode-field{grid-column:2}
.subscription-browser{display:flex;min-height:0;max-height:390px;flex:1;flex-direction:column;gap:10px;padding:0;border:0;border-radius:0;background:transparent}
#create-forward-modal form.fastclient-mode .subscription-node-list{display:flex;min-height:0;flex:1;flex-direction:column;gap:7px;max-height:390px;overflow:auto;padding-right:2px}
#create-forward-modal form.fastclient-mode .subscription-node-card{height:auto;padding:9px 10px}
@media(max-width:760px){#create-forward-modal form.fastclient-mode .forward-primary{grid-template-columns:1fr}#create-forward-modal form.fastclient-mode .subscription-composer,#create-forward-modal form.fastclient-mode .forward-search-field,#create-forward-modal form.fastclient-mode .forward-name-field,#create-forward-modal form.fastclient-mode .forward-quota-field,#create-forward-modal form.fastclient-mode .forward-expire-field,#create-forward-modal form.fastclient-mode .forward-mode-field{grid-column:1;grid-row:auto}.subscription-browser{min-height:0}#create-forward-modal form.fastclient-mode .subscription-node-list{max-height:260px}
  #create-forward-modal .forward-primary,#create-forward-modal form.fastclient-mode .forward-primary{grid-template-columns:1fr}
  #create-forward-modal .forward-secondary,#create-forward-modal form.fastclient-mode .forward-secondary{align-items:stretch;flex-direction:column}
  #create-forward-modal .forward-secondary .actions{width:100%}
  #create-forward-modal .forward-secondary .actions button{flex:1}
}
/* Sidebar refresh: clearer navigation hierarchy and a compact host status card. */
.app-shell{grid-template-columns:256px minmax(0,1fr)}
.sidebar{padding:20px 14px 14px;background:#fbfcfe;border-right-color:#e5e9f0}
.brand{gap:12px;padding:5px 7px 18px;border-bottom:0}
.brand-mark{width:40px;height:40px;border-radius:13px;font-size:19px;box-shadow:0 5px 14px rgba(0,113,227,.18)}
.brand b{font-size:18px}.brand span{font-size:11px}
.sidebar-toggle{width:32px;height:32px;border-radius:10px;background:#fff}
.side-nav{gap:5px;padding:16px 0 0}
.nav-item{min-height:44px;gap:12px;padding:10px 11px;border-radius:10px;color:#667085;font-size:14px}
.nav-item:hover{background:#f1f5f9}.nav-item.active{position:relative;border-color:#d7e6ff;background:#eaf3ff;color:#0875e1;box-shadow:inset 3px 0 0 #0875e1}
.nav-icon{width:20px}.nav-icon svg{width:20px;height:20px;stroke-width:1.9}
.sidebar-bottom{margin:18px -2px 0;padding:12px;border:0;border-radius:14px;background:#f3f7fc}
.sidebar-host{gap:10px;padding:0 0 11px}.sidebar-host b{font-size:13px}.sidebar-host div span{font-size:11px}.sidebar-bottom .online-dot{box-shadow:0 0 0 3px rgba(34,160,83,.12)}
.logout-button{min-height:34px;border-color:#d6dee9;background:#fff;color:#475467}.logout-button:hover{background:#f8fafc}
.app-shell.sidebar-collapsed{grid-template-columns:76px minmax(0,1fr)}
.app-shell.sidebar-collapsed .sidebar{padding-inline:12px}.app-shell.sidebar-collapsed .sidebar-bottom{padding:10px 6px;background:transparent}.app-shell.sidebar-collapsed .side-nav::before{display:none}
/* Collapse labels horizontally instead of removing them abruptly. */
.brand-copy,.nav-label,.sidebar-host div{display:block;max-width:170px;overflow:hidden;opacity:1;transform:translateX(0);white-space:nowrap;transition:max-width .22s ease,opacity .14s ease,transform .22s ease}
.nav-item{transition:background-color .15s ease,border-color .15s ease,color .15s ease,padding .22s ease,gap .22s ease}
.app-shell.sidebar-collapsed .brand-copy,.app-shell.sidebar-collapsed .nav-label,.app-shell.sidebar-collapsed .sidebar-host div,
html.sidebar-pref-collapsed .app-shell .brand-copy,html.sidebar-pref-collapsed .app-shell .nav-label,html.sidebar-pref-collapsed .app-shell .sidebar-host div{display:block;max-width:0;opacity:0;transform:translateX(-7px);pointer-events:none}
.app-shell.sidebar-collapsed .nav-item,html.sidebar-pref-collapsed .app-shell .nav-item{justify-content:flex-start;gap:0;padding-inline:15px}
.app-shell.sidebar-collapsed .sidebar-host,html.sidebar-pref-collapsed .app-shell .sidebar-host{justify-content:flex-start;padding-inline:9px}
/* Keep host status and logout anchored at the bottom of the sidebar. */
.sidebar-bottom{position:sticky;bottom:0;z-index:2;flex:none;margin-top:auto}
/* Compact, icon-only footer in collapsed sidebar mode. */
.app-shell.sidebar-collapsed .sidebar-bottom,html.sidebar-pref-collapsed .app-shell .sidebar-bottom{display:flex;align-items:center;flex-direction:column;gap:10px;margin:0 -6px;padding:10px 0;background:transparent}
.app-shell.sidebar-collapsed .sidebar-host,html.sidebar-pref-collapsed .app-shell .sidebar-host{justify-content:center;padding:0}
.app-shell.sidebar-collapsed .logout-button,html.sidebar-pref-collapsed .app-shell .logout-button{width:38px;min-height:38px;height:38px;display:grid;place-items:center;margin:0;padding:0;border-radius:10px;font-size:0}
.app-shell.sidebar-collapsed .logout-button::after,html.sidebar-pref-collapsed .app-shell .logout-button::after{content:'↪';font-size:19px;line-height:1;color:#475467}
/* Collapsed rail alignment: prevent hidden brand text from consuming flex space. */
.app-shell.sidebar-collapsed .brand,html.sidebar-pref-collapsed .app-shell .brand{justify-content:center;padding-inline:0}
.app-shell.sidebar-collapsed .brand-copy,html.sidebar-pref-collapsed .app-shell .brand-copy{flex:0}
.app-shell.sidebar-collapsed .sidebar-bottom,html.sidebar-pref-collapsed .app-shell .sidebar-bottom{margin-top:auto!important;margin-right:-6px;margin-bottom:-6px;margin-left:-6px}
/* Fixed square toggle, centered within the collapsed rail. */
.sidebar-toggle{box-sizing:border-box;inline-size:36px;block-size:36px;min-height:36px;aspect-ratio:1;flex:0 0 36px;padding:0}
.app-shell.sidebar-collapsed .brand,html.sidebar-pref-collapsed .app-shell .brand{width:100%;box-sizing:border-box;justify-content:center}
/* A standalone status dot is ambiguous in the collapsed rail; keep host status in expanded mode only. */
.app-shell.sidebar-collapsed .sidebar-host,html.sidebar-pref-collapsed .app-shell .sidebar-host{display:none}
.app-shell.sidebar-collapsed .sidebar-bottom,html.sidebar-pref-collapsed .app-shell .sidebar-bottom{gap:0}
/* Absolute centering avoids flex gaps from hidden brand content in the collapsed rail. */
.app-shell.sidebar-collapsed .brand,html.sidebar-pref-collapsed .app-shell .brand{position:relative;display:block;min-height:36px;gap:0}
.app-shell.sidebar-collapsed .sidebar-toggle,html.sidebar-pref-collapsed .app-shell .sidebar-toggle{position:absolute;top:0;left:50%;transform:translateX(-50%);margin:0}
.forward-view{
  min-height:0;
  display:flex;
  flex:1;
  flex-direction:column;
}
.forward-list{
  min-height:0;
  display:flex;
  flex:1;
  flex-direction:column;
  overflow:hidden;
  padding:0;
}
.forward-list .tablewrap{
  min-height:0;
  flex:1;
  border:0;
  border-radius:0;
  overflow:auto;
  scrollbar-width:thin;
  scrollbar-color:#b8c0cc transparent;
}
.forward-list table{width:100%;min-width:1280px;table-layout:auto;border-collapse:separate;border-spacing:0}
.forward-list th{
  position:sticky;
  top:0;
  z-index:2;
  padding:10px 8px;
  border-bottom:1px solid var(--line);
  line-height:1.25;
  white-space:normal;
}
.forward-list th,.forward-list td{
  padding:14px 16px;
  overflow:visible;
  text-align:center;
  text-overflow:clip;
  vertical-align:middle;
  white-space:nowrap;
}
.forward-list th:nth-child(1),.forward-list td:nth-child(1){width:270px;min-width:270px}
.forward-list th:nth-child(2),.forward-list td:nth-child(2){width:135px;min-width:135px}
.forward-list th:nth-child(3),.forward-list td:nth-child(3){width:180px;min-width:180px}
.forward-list th:nth-child(4),.forward-list td:nth-child(4){width:135px;min-width:135px}
.forward-list th:nth-child(5),.forward-list td:nth-child(5){width:220px;min-width:220px}
.forward-list th:nth-child(6),.forward-list td:nth-child(6){width:120px;min-width:120px}
.forward-list th:nth-child(7),.forward-list td:nth-child(7){width:120px;min-width:120px}
.forward-list th:nth-child(8),.forward-list td:nth-child(8){width:135px;min-width:135px}
.forward-list th:nth-child(9),.forward-list td:nth-child(9){width:120px;min-width:120px}
.forward-list th:nth-child(10),.forward-list td:nth-child(10){width:135px;min-width:135px}
.forward-list th:nth-child(11),.forward-list td:nth-child(11){
  position:sticky;
  right:0;
  width:170px;
  min-width:170px;
  background:var(--surface);
  box-shadow:-1px 0 0 var(--line-soft);
}
.forward-list th:nth-child(11){z-index:4;background:var(--soft)}
.forward-list tbody tr:hover td:nth-child(11){background:#fafafa}
.copy-link{min-width:96px}
.qr-link{min-width:76px}
.copy-link.copied{border-color:#8ac69a;background:var(--green-soft);color:var(--green)}
.qr-result{display:grid;gap:14px;justify-items:center;text-align:center}
.qr-result img{width:min(100%,280px);height:auto;padding:10px;background:#fff;border:1px solid var(--line);border-radius:var(--radius-sm)}
.qr-link-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;width:100%;align-items:stretch}
.qr-link-row button{align-self:center;white-space:nowrap}
.qr-result textarea{display:block;width:100%;min-height:72px;resize:vertical;overflow-wrap:anywhere;padding:9px;text-align:left;background:var(--soft);border:1px solid var(--line);border-radius:var(--radius-sm);font:11px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}
.forward-list textarea{
  min-width:300px;
  min-height:44px;
  resize:none;
  font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;
}
.panel-heading{
  display:flex;
  justify-content:space-between;
  align-items:flex-start;
  gap:14px;
  padding-bottom:13px;
}
.panel-heading h3{margin:0 0 3px}
.panel-heading p{margin:0}
.services-panel{width:100%}
.service-row{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:16px;
  padding:15px 0;
  border-top:1px solid var(--line-soft);
}
.service-main{display:flex;align-items:center;gap:11px;min-width:0}
.service-main b,.service-main span{display:block}
.service-main b{font-size:14px}
.service-main .muted{margin-top:2px;font-size:12px}
.service-icon{
  width:36px;
  height:36px;
  display:flex;
  align-items:center;
  justify-content:center;
  line-height:0;
  flex:none;
  border-radius:10px;
  background:var(--blue-soft);
  color:var(--blue);
}
.service-icon svg{display:block;width:20px;height:20px;flex:none;margin:0}
/* SVG is absolutely anchored so inherited span/layout rules cannot shift it. */
.service-icon{position:relative;display:block}
.service-icon svg{position:absolute!important;top:50%!important;left:50%!important;display:block!important;margin:0!important;transform:translate(-50%,-50%)!important}
.service-meta{display:flex;align-items:center;justify-content:flex-end;gap:10px;flex-wrap:wrap}

/* Messages, login and modals */
.flash{
  padding:12px 14px;
  border:1px solid #b9dfbf;
  border-radius:12px;
  margin:0 0 16px;
  background:var(--green-soft);
  color:#236735;
}
.flash.error{border-color:#f2c6c2;background:var(--red-soft);color:#b42318}
.login-wrap{
  min-height:100vh;
  display:grid;
  place-items:center;
  padding:24px;
}
.login-card{width:min(100%,410px);padding:30px}
.login-mark{width:44px;height:44px;margin-bottom:18px;border-radius:13px;font-size:22px}
.remember{display:flex;align-items:center;gap:7px;margin-top:13px;color:var(--muted);font-size:13px}
.remember input{width:auto}
.spinner{
  display:inline-block;
  width:14px;
  height:14px;
  margin-right:7px;
  border:2px solid #c7d8ec;
  border-top-color:var(--blue);
  border-radius:50%;
  vertical-align:-2px;
  animation:spin .7s linear infinite;
}
@keyframes spin{to{transform:rotate(360deg)}}
.modal[hidden]{display:none}
.modal{
  position:fixed;
  inset:0;
  z-index:1000;
  display:grid;
  place-items:center;
  padding:20px;
}
.modal-backdrop{position:absolute;inset:0;background:rgba(29,29,31,.46);backdrop-filter:blur(2px)}
.modal-panel{
  position:relative;
  z-index:1;
  width:min(100%,580px);
  max-height:min(88vh,780px);
  overflow:auto;
  padding:24px;
  border:1px solid var(--line);
  border-radius:var(--radius-lg);
  background:var(--surface);
  box-shadow:0 24px 70px rgba(0,0,0,.24);
}
.modal-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px}
.modal-head h2{margin:0}
.modal-close{
  width:34px;
  height:34px;
  min-height:34px;
  padding:0;
  border:1px solid var(--line);
  border-radius:50%;
  background:var(--soft);
  color:var(--muted);
  font-size:22px;
  font-weight:400;
  line-height:1;
}
.modal-close:hover{background:var(--soft-hover);color:var(--text)}
.delete-warning{margin:0 0 12px;color:var(--red)}
.delete-list{
  margin:0;
  padding:10px 12px 10px 30px;
  border:1px solid #f2c6c2;
  border-radius:12px;
  background:#fff8f7;
}
.delete-list:empty{display:none}
.delete-list li{padding:3px 0}
.delete-modal-panel{width:min(100%,520px)}
.logout-confirm-panel{width:min(calc(100% - 32px),400px);padding:28px;text-align:center}
.logout-confirm-panel .modal-head{justify-content:flex-end;margin:-8px -8px 0}
.password-modal-panel{width:min(calc(100% - 32px),440px)}.password-modal-panel h2{margin-bottom:4px}.password-modal-panel .help{margin-bottom:14px}.password-modal-panel .actions{justify-content:flex-end}
.host-detail-panel{padding:0;overflow:hidden}.host-detail-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}.host-detail-item{min-height:78px;padding:15px 17px;border-right:1px solid var(--line-soft);border-bottom:1px solid var(--line-soft)}.host-detail-item:nth-child(3n){border-right:0}.host-detail-item:nth-last-child(-n+3){border-bottom:0}.host-detail-item span,.host-detail-item b{display:block}.host-detail-item span{margin-bottom:6px;color:var(--muted);font-size:12px}.host-detail-item b{overflow:hidden;font-size:14px;text-overflow:ellipsis;white-space:nowrap}@media(max-width:680px){.host-detail-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.host-detail-item:nth-child(3n){border-right:1px solid var(--line-soft)}.host-detail-item:nth-child(2n){border-right:0}.host-detail-item:nth-last-child(-n+3){border-bottom:1px solid var(--line-soft)}.host-detail-item:nth-last-child(-n+2){border-bottom:0}}
.mixed-forward-modal-panel{width:min(calc(100% - 32px),560px)}.mixed-forward-modal-panel h2{margin-bottom:3px}.mixed-forward-node-list{display:grid;gap:9px;margin-top:16px;max-height:360px;overflow:auto}.mixed-forward-node{padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--soft)}.mixed-forward-node b,.mixed-forward-node span{display:block}.mixed-forward-node span{margin-top:4px;color:var(--muted);font-size:12px}.mixed-node-button{padding:0;border:0;border-bottom:1px dashed currentColor;border-radius:0;background:transparent;color:var(--blue);font:inherit;cursor:pointer}.mixed-node-button:hover{background:transparent;color:var(--blue-pressed)}
.logout-confirm-icon{width:52px;height:52px;display:grid;place-items:center;margin:0 auto 14px;border-radius:17px;background:var(--blue-soft);color:var(--blue)}
.logout-confirm-icon svg{width:26px;height:26px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.logout-confirm-panel h2{margin:0 0 8px;font-size:20px}.logout-confirm-panel p{margin:0;color:var(--muted);font-size:13px;line-height:1.6}.logout-confirm-panel .actions{justify-content:center;margin:22px 0 0}.logout-confirm-panel .actions button{min-width:116px}

@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{scroll-behavior:auto!important;transition:none!important}
  .spinner{animation:none}
}
@media(max-width:1100px){
  .forward-grid,#create-forward-modal .forward-grid{grid-template-columns:1fr;gap:8px}
}
@media(max-width:920px){
  .app-shell,.app-shell.sidebar-collapsed{display:block}
  .sidebar,.app-shell.sidebar-collapsed .sidebar{
    position:static;
    width:100%;
    height:auto;
    overflow:visible;
    margin:0;
    padding:14px 16px;
    border-right:0;
    border-bottom:1px solid var(--line);
  }
  .brand,.app-shell.sidebar-collapsed .brand{justify-content:flex-start;padding:2px 4px 13px}
  .app-shell.sidebar-collapsed .brand-mark{display:grid}
  .app-shell.sidebar-collapsed .brand-copy{display:block}
  .sidebar-toggle{display:none}
  .side-nav{display:flex;gap:8px;overflow-x:auto;padding-top:12px;scrollbar-width:thin}
  .nav-item,.app-shell.sidebar-collapsed .nav-item{width:auto;min-width:max-content;justify-content:flex-start;gap:11px;padding-inline:12px}
  .app-shell.sidebar-collapsed .nav-label{display:inline}
  .sidebar-bottom{
    margin-top:12px;
    padding-top:12px;
  }
  .sidebar-host,.app-shell.sidebar-collapsed .sidebar-host{justify-content:flex-start;padding:0}
  .app-shell.sidebar-collapsed .sidebar-host div{display:block}
  .workspace{padding:18px 16px 24px}
  .nodes-panel th:first-child,.nodes-panel td:first-child{
    position:sticky;
    left:0;
    z-index:1;
    background:var(--surface);
    box-shadow:1px 0 0 var(--line-soft);
  }
  .nodes-panel th:first-child{z-index:3;background:var(--soft)}
}
@media(max-width:680px){
  .workspace{padding:16px 12px 20px}
  .view-heading{align-items:flex-start;flex-direction:column;gap:10px}
  .view-heading .section-actions{width:100%}
  .view-heading .section-actions form,.view-heading .section-actions button{flex:1}
  .summary-strip,.host-summary{grid-template-columns:repeat(2,minmax(0,1fr))}
  .summary-strip>div,.host-stat{padding:13px 14px}
  .field-grid{grid-template-columns:1fr}
  .mode{grid-template-columns:1fr}
  .mode label{justify-content:flex-start}
  .table-pagination{align-items:stretch;flex-direction:column}
  .pagination-controls{justify-content:space-between}
  .pagination-pages{justify-content:center}
  .service-row{align-items:flex-start;flex-direction:column}
  .service-meta{justify-content:flex-start}
  .modal{padding:12px}
  .modal-panel{max-height:92vh;padding:19px;border-radius:var(--radius-md)}
  .nodes-panel{overflow:visible;background:transparent;border:0;box-shadow:none}
  .nodes-panel .tablewrap{overflow:visible}
  .nodes-panel table,.nodes-panel tbody{display:block;min-width:0}
  .nodes-panel thead{display:none}
  .nodes-panel .node-row{
    display:grid;
    grid-template-columns:minmax(0,1fr) minmax(0,1fr);
    gap:9px 14px;
    margin-bottom:12px;
    padding:14px;
    border:1px solid var(--line);
    border-radius:var(--radius-md);
    background:var(--surface);
    box-shadow:var(--shadow);
  }
  .nodes-panel .node-row[hidden]{display:none}
  .nodes-panel .node-row td{
    position:static!important;
    width:auto!important;
    min-width:0;
    padding:0;
    overflow:visible;
    border:0;
    box-shadow:none!important;
    text-align:left;
    text-overflow:clip;
    white-space:normal;
  }
  .nodes-panel .node-row td::before{display:block;margin-bottom:2px;color:var(--muted);font-size:11px}
  .nodes-panel .node-row td:nth-child(1)::before{content:"用户"}
  .nodes-panel .node-row td:nth-child(2)::before{content:"到期日期"}
  .nodes-panel .node-row td:nth-child(3)::before{content:"节点地区"}
  .nodes-panel .node-row td:nth-child(4)::before{content:"地址"}
  .nodes-panel .node-row td:nth-child(5)::before{content:"端口"}
  .nodes-panel .node-row td:nth-child(6)::before{content:"延迟"}
  .nodes-panel .node-row td:nth-child(7)::before{content:"下载速度"}
  .nodes-panel .node-row td:nth-child(8)::before{content:"状态"}
  .nodes-panel .node-row td:nth-child(9){grid-column:1/-1;padding-top:4px}
  .nodes-panel .node-row td:nth-child(9)::before{content:"操作"}
  .nodes-panel .row-actions{justify-content:flex-start;flex-wrap:wrap}
  .nodes-panel .row-actions button{min-height:36px;padding-inline:14px}
  .table-pagination{border:1px solid var(--line);border-radius:var(--radius-md);box-shadow:var(--shadow)}
}
/* Mobile app shell: persistent bottom tab bar instead of top navigation. */
@media(max-width:920px){
  .sidebar,.app-shell.sidebar-collapsed .sidebar{padding:14px 16px 12px;background:#fff}
  .brand,.app-shell.sidebar-collapsed .brand{padding:2px 4px 10px}
  .sidebar-bottom{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0;padding:10px 4px 0;border:0;border-radius:0;background:transparent}
  .sidebar-host,.app-shell.sidebar-collapsed .sidebar-host{padding:0}.sidebar-bottom .logout-button{width:auto;min-height:34px;padding:7px 12px;font-size:12px}
  .side-nav{position:fixed;right:0;bottom:0;left:0;z-index:50;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0;overflow:visible;padding:6px 10px calc(6px + env(safe-area-inset-bottom));border-top:1px solid var(--line);background:rgba(255,255,255,.96);box-shadow:0 -8px 24px rgba(16,24,40,.08);backdrop-filter:blur(12px)}
  .nav-item,.app-shell.sidebar-collapsed .nav-item{width:100%;min-width:0;min-height:52px;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:3px;padding:5px 4px;border:0;border-radius:10px;font-size:11px;line-height:1.15}
  .nav-item.active{box-shadow:none;background:var(--blue-soft);color:var(--blue)}
  .nav-icon{width:auto;height:20px}.nav-icon svg{width:19px;height:19px}
  .nav-label,.app-shell.sidebar-collapsed .nav-label{display:block;max-width:none;opacity:1;transform:none;white-space:nowrap}
  .workspace{padding:18px 16px calc(88px + env(safe-area-inset-bottom))}
  .host-summary{grid-template-columns:repeat(2,minmax(0,1fr))}
}
/* Refined mobile node inventory cards. */
@media(max-width:680px){
  .view-heading .section-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
  .view-heading .section-actions form,.view-heading .section-actions button{width:100%;min-width:0;margin:0}
  .nodes-panel .node-row{gap:14px 18px;margin-bottom:14px;padding:16px;border-radius:14px;box-shadow:0 2px 8px rgba(16,24,40,.04)}
  .nodes-panel .node-row td,.nodes-panel .node-row td:nth-child(9){background:transparent!important}
  .nodes-panel .node-row td::before{margin-bottom:4px;font-size:11px;font-weight:500}
  .nodes-panel .node-row td:nth-child(9){margin-top:2px;padding-top:12px;border-top:1px solid var(--line-soft)}
  .nodes-panel .row-actions{gap:8px}.nodes-panel .row-actions button{flex:1;padding-inline:8px}
  .nodes-panel .table-pagination{margin-top:2px;border:0;border-radius:0;box-shadow:none;background:transparent}
}
/* Compact mobile node table: retain core identity columns and hide secondary diagnostics. */
@media(max-width:920px){
  .nodes-panel{overflow:hidden;background:var(--surface);border:1px solid var(--line);box-shadow:var(--shadow)}
  .nodes-panel .tablewrap{overflow:auto}.nodes-panel table{display:table;width:100%;min-width:620px;table-layout:fixed}.nodes-panel tbody{display:table-row-group}.nodes-panel thead{display:table-header-group}
  .nodes-panel .node-row{display:table-row;margin:0;padding:0;border:0;border-radius:0;background:transparent;box-shadow:none}
  .nodes-panel .node-row td{display:table-cell;position:static!important;width:auto!important;min-width:0;padding:12px 8px;overflow:hidden;border-bottom:1px solid var(--line-soft);background:transparent!important;box-shadow:none!important;text-align:center;text-overflow:ellipsis;vertical-align:middle;white-space:nowrap}
  .nodes-panel .node-row td::before{display:none}.nodes-panel .node-row td:nth-child(9){display:table-cell;margin:0;padding:10px 8px;border-top:0;background:var(--surface)!important}
  .nodes-panel th,.nodes-panel td{font-size:12px}.nodes-panel th:nth-child(1),.nodes-panel td:nth-child(1){width:100px;min-width:100px}.nodes-panel th:nth-child(2),.nodes-panel td:nth-child(2){width:112px;min-width:112px}.nodes-panel th:nth-child(3),.nodes-panel td:nth-child(3){width:110px;min-width:110px}.nodes-panel th:nth-child(4),.nodes-panel td:nth-child(4){width:135px;min-width:135px}.nodes-panel th:nth-child(9),.nodes-panel td:nth-child(9){width:163px;min-width:163px}
  .nodes-panel th:nth-child(5),.nodes-panel td:nth-child(5),.nodes-panel th:nth-child(6),.nodes-panel td:nth-child(6),.nodes-panel th:nth-child(7),.nodes-panel td:nth-child(7),.nodes-panel th:nth-child(8),.nodes-panel td:nth-child(8){display:none}
  .nodes-panel .row-actions{display:flex;gap:5px;justify-content:center;flex-wrap:nowrap}.nodes-panel .row-actions button{min-height:34px;flex:1;padding:6px 7px;font-size:12px}
}
/* On phones, keep only the bottom navigation; brand and account controls do not need a header. */
@media(max-width:920px){
  .sidebar,.app-shell.sidebar-collapsed .sidebar{height:0;min-height:0;overflow:visible;padding:0;border:0}
  .sidebar .brand,.sidebar .sidebar-bottom{display:none!important}
}
/* Service controls remain managed in the backend but are not displayed in the dashboard. */
.services-panel{display:none}
/* Subscription token rotation controls are intentionally hidden from the dashboard. */
.token-panel{display:none}
/* Host details use the same individual-card treatment as the summary metrics. */
.host-detail-panel{padding:0!important;overflow:visible!important;border:0!important;background:transparent!important;box-shadow:none!important}
.host-detail-grid{grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:0 0 14px}
.host-detail-item,.host-detail-item:nth-child(n){min-width:0;min-height:0;padding:15px 17px;border:1px solid var(--line);border-radius:var(--radius-md);background:var(--surface);box-shadow:0 3px 12px rgba(0,0,0,.025)}
.host-detail-item span{margin-bottom:6px;font-size:12px}.host-detail-item b{overflow-wrap:anywhere;font-size:16px;line-height:1.3;text-overflow:clip;white-space:normal}
@media(max-width:680px){.host-detail-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.host-detail-item,.host-detail-item:nth-child(n){border:1px solid var(--line)}}
</style>
</head>
<body><main>{{BODY}}</main><script src="/app.js" defer></script></body>
</html>'''


APP_JS = APP_JS.replace('  /* DELETE_DIALOG */', (APP_DIR / 'delete-dialog.js').read_text(encoding='utf-8'))
APP_JS = APP_JS.replace('  /* CONSOLE_EXTENSION */', (APP_DIR / 'console.js').read_text(encoding='utf-8'))
HTML_HEAD = HTML_HEAD.replace('</style>', (APP_DIR / 'console.css').read_text(encoding='utf-8') + '\n</style>')


def page(body, title='Relay · 中转控制台'):
    return HTML_HEAD.replace('{{TITLE}}', esc(title)).replace('{{BODY}}', body)


def login_page(error=''):
    message = '<div class="flash error">%s</div>' % esc(error) if error else ''
    body = '<section class="login-wrap"><div class="card login-card"><div class="login-mark">R</div><h1>Relay</h1><p class="muted">安全的中转节点管理</p>%s<form method="post" action="/login"><label>账户</label><input name="username" autocomplete="username" required autofocus><label>密码</label><input type="password" name="password" autocomplete="current-password" required><label class="remember"><input type="checkbox" name="remember" value="1" checked>保持登录 30 天</label><div class="actions"><button type="submit">登录管理面板</button></div></form></div></section>' % message
    return page(body, '登录 · Relay')


def host_snapshot():
    """Return a lightweight status snapshot for the host and managed Xray services."""
    try:
        with open('/proc/uptime', 'r', encoding='ascii') as f:
            uptime_seconds = int(float(f.read().split()[0]))
    except Exception:
        uptime_seconds = 0
    days, remainder = divmod(uptime_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    uptime_text = ('%d天 ' % days if days else '') + '%02d小时 %02d分钟' % (hours, minutes)
    try:
        load1 = '%.2f' % os.getloadavg()[0]
    except (AttributeError, OSError):
        load1 = '—'
    try:
        usage = os.statvfs('/')
        total = usage.f_blocks * usage.f_frsize
        free = usage.f_bavail * usage.f_frsize
        disk_used = round((1 - free / total) * 100, 1) if total else 0
    except OSError:
        disk_used = None
    disk_text = format_traffic_bytes(int(total - free)) + ' / ' + format_traffic_bytes(int(total)) if disk_used is not None else '—'
    mem_total = mem_available = 0
    try:
        values = {}
        with open('/proc/meminfo', 'r', encoding='ascii') as f:
            for line in f:
                key, value = line.split(':', 1)
                values[key] = int(value.strip().split()[0]) * 1024
        mem_total, mem_available = values.get('MemTotal', 0), values.get('MemAvailable', 0)
    except Exception:
        pass
    memory_text = format_traffic_bytes(max(0, mem_total - mem_available)) + ' / ' + format_traffic_bytes(mem_total) if mem_total else '—'
    try:
        os_values = {}
        with open('/etc/os-release', 'r', encoding='utf-8') as f:
            for line in f:
                if '=' in line:
                    key, value = line.rstrip().split('=', 1)
                    os_values[key] = value.strip('"')
        os_name = os_values.get('PRETTY_NAME', platform.system())
    except Exception:
        os_name = platform.system()
    cpu_model = ''
    try:
        with open('/proc/cpuinfo', 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.lower().startswith('model name'):
                    cpu_model = line.split(':', 1)[1].strip()
                    break
    except Exception:
        pass
    cpu_text = '%s vCPU%s' % (os.cpu_count() or 1, (' · ' + cpu_model) if cpu_model else '')
    public_ip = '—'
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(('1.1.1.1', 80))
        public_ip = probe.getsockname()[0]
        probe.close()
    except OSError:
        pass
    services = {}
    for key, cfg in CONFIGS.items():
        unit = subprocess.run(['systemctl', 'cat', cfg['service']], capture_output=True, text=True, timeout=5)
        if unit.returncode:
            continue
        active, enabled = service_state(cfg['service'])
        services[key] = {'service': cfg['service'], 'entry': cfg['entry'], 'active': active, 'enabled': enabled}
    return {'hostname': socket.gethostname(), 'uptime_seconds': uptime_seconds, 'uptime_text': uptime_text,
            'load1': load1, 'disk_used_percent': disk_used, 'disk_text': disk_text, 'memory_text': memory_text,
            'public_ip': public_ip, 'os_name': os_name, 'cpu_text': cpu_text, 'kernel': platform.release(),
            'services': services, 'checked_at': int(time.time())}


def revoke_other_sessions(current_sid):
    with MUTEX:
        state = load_state()
        state['sessions'] = {key: value for key, value in state.get('sessions', {}).items() if key == current_sid}
        save_state(state)
        for sid in list(SESSIONS):
            if sid != current_sid:
                SESSIONS.pop(sid, None)


def console_overview(nodes, state, clients, healthy, latency):
    forwards = forwarding_rows(state, clients)
    today = date.today()
    soon = 0
    for item in forwards:
        try:
            remaining = (date.fromisoformat(item.get('expires_on', '')) - today).days
            soon += 0 <= remaining <= 7
        except (ValueError, TypeError):
            pass
    cards = [(str(len(nodes)), '上游节点', '集中管理 · 多协议接入', ''),
             (str(len(forwards)), '转发服务', 'SOCKS5 / VLESS / 订阅', ''),
             (str(latency) + ' ms' if latency is not None else '—', '平均延迟', '基于最近一次成功检测', ''),
             (str(soon), '即将到期', '未来 7 天内到期的转发', ' attention' if soon else '')]
    markup = '<header class="console-header"><div><h1>中转控制台</h1></div><span class="console-live"><span class="online-dot %s"></span>%s</span></header>' % ('' if healthy else 'offline', '入口服务正常' if healthy else '入口服务异常')
    markup += '<div class="console-stats">'
    for value, label, note, extra in cards:
        markup += '<div class="console-stat%s"><span>%s</span><b>%s</b><small>%s</small></div>' % (extra, esc(label), esc(value), esc(note))
    return markup + '</div>'


def dashboard(csrf, flash='', error='', active_view='nodes-view'):
    state = load_state()
    nodes = node_inventory(state)
    clients = client_rows(state)
    host = host_snapshot()
    tests = [state.get('node_meta', {}).get(n['config'] + '::' + n['tag'], {}).get('test', {}) for n in nodes]
    successful_tests = [x for x in tests if x and not x.get('error')]
    avg_latency = round(sum(float(x.get('latency_ms', 0)) for x in successful_tests) / len(successful_tests)) if successful_tests else None
    running_services = sum(1 for x in host['services'].values() if x['active'] == 'active')
    esc_csrf = esc(csrf)
    today = date.today().isoformat()
    all_services_healthy = bool(host['services']) and running_services == len(host['services'])
    nodes_view_attr = '' if active_view == 'nodes-view' else ' hidden'
    forward_view_attr = '' if active_view == 'forward-view' else ' hidden'
    host_view_attr = '' if active_view == 'host-view' else ' hidden'
    parts = [
        '<div class="app-shell sidebar-initializing"><aside class="sidebar" id="app-sidebar">'
        '<div class="brand"><div class="brand-mark">R</div>'
        '<div class="brand-copy"><b>Relay</b><span>%s</span></div>'
        '<button type="button" class="sidebar-toggle" data-sidebar-toggle aria-controls="app-sidebar" aria-expanded="true" aria-label="收起侧边栏" title="收起侧边栏">'
        '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m14 6-6 6 6 6"/></svg></button></div>'
        '<nav class="side-nav" aria-label="功能导航">'
        '<button type="button" class="nav-item%s" data-view-target="nodes-view" data-view-url="/nodes" data-view-title="节点管理" title="节点管理">'
        '<span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="5" rx="1"/><rect x="3" y="10" width="18" height="5" rx="1"/><rect x="3" y="16" width="18" height="5" rx="1"/><path d="M7 7h.01M7 13h.01M7 19h.01"/></svg></span><span class="nav-label">节点管理</span></button>'
        '<button type="button" class="nav-item%s" data-view-target="forward-view" data-view-url="/forward" data-view-title="转发创建" title="转发创建">'
        '<span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12h15"/><path d="m13 6 6 6-6 6"/></svg></span><span class="nav-label">转发创建</span></button>'
        '<button type="button" class="nav-item%s" data-view-target="host-view" data-view-url="/host" data-view-title="主机状态" title="主机状态">'
        '<span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16v14H4z"/><path d="M7 15l2-3 2 2 3-4 3 5"/><path d="M8 9h.01"/></svg></span><span class="nav-label">主机状态</span></button>'
        '</nav><div class="sidebar-bottom"><div class="sidebar-host"><span class="online-dot %s"></span>'
        '<div><b>%s</b><span>%s</span></div></div><form class="confirm-logout-form" method="post" action="/logout"><input type="hidden" name="csrf" value="%s"><button class="secondary logout-button" type="submit" aria-label="安全退出" title="安全退出">安全退出</button></form></div></aside><div class="workspace">' % (esc(RELAY_LABEL), ' active' if active_view == 'nodes-view' else '', ' active' if active_view == 'forward-view' else '', ' active' if active_view == 'host-view' else '', '' if all_services_healthy else 'offline', esc(RELAY_LABEL), esc(PUBLIC_HOST), esc_csrf)
    ]

    if flash:
        parts.append('<div class="flash" role="status">%s</div>' % esc(flash))
    if error:
        parts.append('<div class="flash error" role="alert">%s</div>' % esc(error))
    parts.append(('<section id="nodes-view" class="view nodes-view"%s><div class="view-heading"><div><h2>节点管理</h2></div><div class="section-actions"><form class="test-all-form" method="post" action="/node/test-all"><input type="hidden" name="csrf" value="%s"><button>一键检测全部</button></form><button type="button" class="secondary" data-modal-open="add-node-modal">添加节点</button></div></div><section class="panel nodes-panel"><div class="tablewrap"><table><thead><tr><th>用户</th><th>到期日期</th><th>节点地区</th><th>地址</th><th>端口</th><th>延迟 (ms)</th><th>下载速度 (Mbps)</th><th>状态</th><th>操作</th></tr></thead><tbody>' % (nodes_view_attr, esc_csrf)))
    for n in nodes:
        test = state.get('node_meta', {}).get(n['config'] + '::' + n['tag'], {}).get('test', {})
        if test.get('error'):
            latency_text = speed_text = '—'
            status_text = '<span class="status-badge bad">检测失败</span><span class="help"> · %s</span>' % esc(test['error'])
        elif test:
            latency_text = latency_markup(test.get('latency_ms'))
            speed_value = test.get('speed_mbps')
            speed_text = ('%s Mbps' % esc(speed_value)) if speed_value is not None else '—'
            status_text = '<span class="status-badge ok"><span class="online-dot"></span>可用</span>'
        else:
            latency_text = speed_text = '—'
            status_text = '<span class="muted">未检测</span>'
        node_key = n['config'] + '::' + n['tag']
        button = '<form class="node-test-form" data-node="%s" method="post" action="/node/test"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="node" value="%s"><button class="secondary" type="submit">检测</button></form>' % (esc(node_key), esc_csrf, esc(node_key))
        edit_button = '<button type="button" class="secondary" data-modal-open="edit-node-modal" data-edit-config="%s" data-edit-tag="%s" data-edit-user="%s" data-edit-country="%s" data-edit-activated-on="%s" data-edit-duration-days="%s" data-edit-expires-on="%s">编辑</button>' % (esc(n['config']), esc(n['tag']), esc(n['user']), esc(n['country']), esc(n['activated_on']), esc(n['duration_days']), esc(n['expires_on']))
        delete_button = '<form class="node-delete-form" data-node="%s" data-node-label="%s:%s" method="post" action="/node/delete"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="config" value="%s"><input type="hidden" name="tag" value="%s"><input type="hidden" name="confirm" value="0"><button class="danger" type="submit">删除</button></form>' % (esc(node_key), esc(n['address']), esc(n['port']), esc_csrf, esc(n['config']), esc(n['tag']))
        parts.append('<tr class="node-row" data-node="%s"><td class="mono">%s</td><td>%s</td><td>%s</td><td class="mono">%s</td><td>%s</td><td class="test-result metric" data-node="%s" data-metric="latency">%s</td><td class="test-result metric" data-node="%s" data-metric="speed">%s</td><td class="test-result status-cell" data-node="%s" data-metric="status">%s</td><td><div class="row-actions">%s%s%s</div></td></tr>' % (esc(node_key), esc(n['user'] or '—'), esc(n['expires_on'] or '—'), esc(n['country']), esc(n['address']), esc(n['port']), esc(node_key), latency_text, esc(node_key), speed_text, esc(node_key), status_text, button, edit_button, delete_button))
    parts.append('</tbody></table></div><div class="table-pagination" data-node-pagination><span class="muted" data-pagination-summary>共 0 个节点</span><div class="pagination-controls"><button type="button" class="secondary" data-pagination-prev disabled>上一页</button><div class="pagination-pages" data-pagination-pages></div><button type="button" class="secondary" data-pagination-next disabled>下一页</button></div></div></section></section>')

    forward_nodes = list(nodes)
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        direct = find_outbound(data, 'direct') or next((x for x in data.get('outbounds', []) if x.get('protocol') == 'freedom'), None)
        if direct:
            direct_tag = direct.get('tag', 'direct')
            if not any(node['config'] == key and node['tag'] == direct_tag for node in forward_nodes):
                active, enabled = service_state(cfg['service'])
                forward_nodes.insert(0, {'config': key, 'service': cfg['service'], 'entry': cfg['entry'], 'inbound': cfg['inbound'],
                                        'tag': direct_tag, 'protocol': 'freedom', 'address': PUBLIC_HOST, 'port': cfg['entry'],
                                        'username': '', 'user': '本机', 'country': '本机直连', 'activated_on': '',
                                        'duration_days': '', 'expires_on': '', 'routes': route_info(data, direct_tag),
                                        'default': fallback_tag(data, cfg) == direct_tag, 'active': active, 'enabled': enabled})
    forward_node_options = ''.join(
        '<option value="%s::%s"%s>%s:%s · %s · 用户：%s</option>' % (
            esc(node['config']), esc(node['tag']), ' selected' if node.get('default') else '',
            esc(node['address']), esc(node['port']), esc(node['country']), esc(node['user'] or '未填写'))
        for node in forward_nodes)
    subscription_users = []
    subscription_user_ids = {}
    for node in forward_nodes:
        user_name = node['user'] or '未填写'
        if user_name not in subscription_user_ids:
            subscription_user_ids[user_name] = 'subscription-user-%d' % len(subscription_users)
            subscription_users.append({'id': subscription_user_ids[user_name], 'name': user_name, 'nodes': []})
        node['_subscription_user_id'] = subscription_user_ids[user_name]
        next(item for item in subscription_users if item['id'] == node['_subscription_user_id'])['nodes'].append(node)
    subscription_user_items = ''.join(
        '<button type="button" class="subscription-user-item%s" data-subscription-user-select="%s" data-subscription-search="%s"><span>%s</span><small>%d 个配置</small></button>' % (' active' if index == 0 else '', esc(item['id']), esc(item['name']), esc(item['name']), len(item['nodes']))
        for index, item in enumerate(subscription_users))
    subscription_node_cards = ''.join(
        ('<div class="subscription-node-card" data-subscription-user="%s"%s><label class="subscription-node-check">'
         '<input type="checkbox" data-subscription-node value="%s::%s">'
         '<span><b>%s:%s</b><small>%s · 用户：%s</small></span></label><label class="subscription-node-name">客户端显示名称'
         '<input type="text" data-subscription-node-label maxlength="80" value="%s" disabled></label></div>') % (esc(node['_subscription_user_id']), '', esc(node['config']), esc(node['tag']), esc(node['address']), esc(node['port']), esc(node['country']), esc(node['user'] or '未填写'), esc(node['country'] or node['tag'])) for index, node in enumerate(forward_nodes))
    parts.append(
        ('<div class="modal" id="create-forward-modal" role="dialog" aria-modal="true" aria-labelledby="create-forward-title" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="create-forward-title">创建转发</h2>'
         '<button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div>'
         '<form class="async-form" method="post" action="/forward/create"><input type="hidden" name="csrf" value="%s">'
         '<input type="hidden" name="entry" value=""><div class="form-error" role="alert" hidden></div><div class="forward-grid">'
         '<div class="forward-primary">'
         '<div class="forward-upstream-field" data-forward-upstream><label>转发对象（上游节点）</label><select name="upstream">%s</select></div>'
         '<section class="subscription-composer" data-forward-subscription hidden><input type="hidden" name="subscription_nodes" value="">'
         '<div class="subscription-browser"><div class="subscription-node-list">%s</div></div></section>'
         '<div class="forward-search-field"><label>搜索节点</label><input type="search" data-subscription-node-search placeholder="用户、地区、地址或端口" aria-label="搜索节点和用户"></div><div class="forward-name-field"><label data-forward-label>转发名称</label><input name="label" placeholder="例如：台湾住宅出口" required maxlength="80"></div><div class="forward-quota-field"><label>流量额度 GB</label><input name="quota_total_gb" type="number" min="1" step="1" value="500" required></div><div class="forward-expire-field"><label>到期日期（当日 00:00 停止）</label><input name="quota_expires_on" type="date" value="%s" required></div>'
         '<div class="forward-mode-field"><label>输出方式</label><div class="mode"><label><input type="radio" name="mode" value="socks" checked>SOCKS5</label>'
         '<label><input type="radio" name="mode" value="vless">VLESS</label><label><input type="radio" name="mode" value="subscription">FastClient 订阅</label></div></div></div>'
         '<div class="forward-secondary">'
         '<div class="actions"><button type="submit">创建并启用转发</button><button type="button" class="secondary" data-modal-close>取消</button></div>'
         '</div></div></form></section></div>') % (esc_csrf, forward_node_options, subscription_node_cards, (date.today() + timedelta(days=30)).isoformat())
    )
    parts.append('<section id="forward-view" class="view forward-view"%s><div class="view-heading"><div><h2>转发管理</h2></div><button type="button" data-modal-open="create-forward-modal">创建转发</button></div><section class="panel forward-list"><div class="tablewrap"><table><thead><tr><th>名称</th><th>方式</th><th>IP</th><th>地区</th><th>用户</th><th>流量额度</th><th>流量使用量</th><th>到期日期</th><th>订阅状态</th><th>访问 / 导入信息</th><th>操作</th></tr></thead><tbody>' % forward_view_attr)
    forwards = forwarding_rows(state, clients)
    node_display = {n['config'] + '::' + n['tag']: ('%s:%s' % (n['address'], n['port']), n['country'] or '—', n['user'] or '未填写') for n in nodes}
    node_display_by_tag = {n['tag']: ('%s:%s' % (n['address'], n['port']), n['country'] or '—', n['user'] or '未填写') for n in nodes}
    if forwards:
        for row in forwards:
            value = row['value']
            upstream_values = node_display.get(str(row.get('upstream_config', '')) + '::' + row['upstream'], node_display_by_tag.get(row['upstream']))
            if upstream_values is None:
                upstream_values = (row['upstream'], '—', '—')
            upstream_ip, upstream_country, upstream_user = upstream_values
            upstream_ip_cell = esc(upstream_ip)
            if row.get('upstream_count', 1) > 1:
                details = []
                for item in row.get('subscription_nodes', []):
                    values = node_display.get(str(item.get('config', '')) + '::' + str(item.get('upstream', '')), node_display_by_tag.get(item.get('upstream', ''), ('—', '—', '未填写')))
                    details.append({'label': item.get('label', ''), 'address': values[0], 'country': values[1], 'user': values[2]})
                upstream_ip = '%d 个节点' % row['upstream_count']
                upstream_ip_cell = '<button type="button" class="mixed-node-button" data-mixed-forward-nodes="%s">%s</button>' % (esc(json.dumps(details, ensure_ascii=False)), esc(upstream_ip))
                upstream_country = 'FastClient 组合'
                upstream_user = '已分别命名'
            rename = ''
            if row['mode'] in ('external_subscription', 'subscription'):
                rename = '<button type="button" class="secondary" data-modal-open="edit-forward-title-modal" data-forward-id="%s" data-forward-title="%s">改名</button>' % (esc(row['id']), esc(row['label']))
            delete_form = '<form class="confirm-delete-form async-form" data-return-view="forward-view" method="post" action="/forward/delete"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s"><input type="hidden" name="confirm" value="1"><button class="danger">删除</button></form>' % (esc_csrf, esc(row['id']))
            status = row.get('status', {'class': 'neutral', 'text': '未设置'})
            status_cell = '<span class="status-badge %s">%s</span>' % (esc(status.get('class', 'neutral')), esc(status.get('text', '')))
            parts.append('<tr class="forward-row"><td><b>%s</b></td><td><span class="kind %s">%s</span></td><td class="mono">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><div class="row-actions"><button type="button" class="secondary copy-link" data-copy-value="%s" aria-label="复制 %s 的访问或导入信息">复制链接</button><button type="button" class="secondary qr-link" data-qr-forward="%s" data-qr-label="%s" data-qr-value="%s">二维码</button></div></td><td><div class="row-actions">%s%s</div></td></tr>' % (esc(row['label']), 'vless' if row['mode'] != 'socks' else '', esc(row['mode_name']), upstream_ip_cell, esc(upstream_country), esc(upstream_user), esc(row.get('quota_total_display', '未设置')), esc(row.get('quota_used_display', '0B')), esc(row.get('expires_on', '未设置')), status_cell, esc(value), esc(row['label']), esc(row['id']), esc(row['label']), esc(value), rename, delete_form))
    else:
        parts.append('<tr><td colspan="11" class="empty">尚未创建转发。先选择一个可用节点。</td></tr>')
    parts.append('</tbody></table></div><div class="table-pagination" data-forward-pagination><span class="muted" data-forward-pagination-summary>共 0 条转发</span><div class="pagination-controls"><button type="button" class="secondary" data-forward-pagination-prev disabled>上一页</button><div class="pagination-pages" data-forward-pagination-pages></div><button type="button" class="secondary" data-forward-pagination-next disabled>下一页</button></div></div></section></section>')

    def service_row(key, item):
        active = item['active'] == 'active'
        active_class = 'ok' if active else 'bad'
        active_text = '运行中' if active else item['active']
        enabled_text = '开机启用' if item['enabled'] == 'enabled' else item['enabled']
        return '<div class="service-row" data-service="%s"><div class="service-main"><span class="service-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 9h8M8 13h8M8 17h4"/></svg></span><div><b>%s</b></div></div><div class="service-meta"><span class="status-badge %s" data-service-active><span class="online-dot"></span>%s</span><span class="status-badge neutral" data-service-enabled>%s</span><form method="post" action="/service/restart"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="config" value="%s"><button class="secondary" type="submit">重启</button></form></div></div>' % (esc(key), esc('Xray ' + key), active_class, esc(active_text), esc(enabled_text), esc_csrf, esc(key))

    disk_text = '%s%%' % host['disk_used_percent'] if host['disk_used_percent'] is not None else '—'
    service_rows = ''.join(service_row(key, item) for key, item in host['services'].items())
    feed_forms = ''.join('<form class="confirm-rotate-form" method="post" action="/feeds/rotate"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="scope" value="%s"><button class="secondary" type="submit">轮换 %s 订阅令牌</button></form>' % (esc_csrf, esc(scope), esc('全部' if scope == 'all' else str(CONFIGS[scope]['entry']))) for scope in ('all', *CONFIGS))
    checked_class = 'ok' if all_services_healthy else 'bad'
    checked_text = '全部正常' if all_services_healthy else '发现故障'
    parts.append('<section id="host-view" class="view"%s>%s<div class="view-heading"><div><h2>主机状态</h2></div><div class="section-actions"><button type="button" class="secondary" data-modal-open="change-password-modal">修改密码</button><button type="button" class="secondary" data-host-refresh>刷新状态</button></div></div><div class="host-summary"><div class="host-stat"><span>主机名</span><b data-host-field="hostname">%s</b></div><div class="host-stat"><span>运行时长</span><b data-host-field="uptime_text">%s</b></div><div class="host-stat"><span>系统负载</span><b data-host-field="load1">%s</b></div><div class="host-stat"><span>磁盘占用</span><b data-host-field="disk_used_percent">%s</b></div></div><section class="panel host-detail-panel"><div class="host-detail-grid"><div class="host-detail-item"><span>公网 IP</span><b data-host-field="public_ip">%s</b></div><div class="host-detail-item"><span>操作系统</span><b data-host-field="os_name">%s</b></div><div class="host-detail-item"><span>CPU 配置</span><b data-host-field="cpu_text">%s</b></div><div class="host-detail-item"><span>内存使用</span><b data-host-field="memory_text">%s</b></div><div class="host-detail-item"><span>磁盘用量</span><b data-host-field="disk_text">%s</b></div><div class="host-detail-item"><span>内核版本</span><b data-host-field="kernel">%s</b></div></div></section><section class="panel services-panel"><div class="panel-heading"><div><h3>入口服务</h3></div><span class="status-badge %s" data-host-field="checked_label">%s</span></div>%s</section><section class="panel token-panel"><div class="panel-heading"><div><h3>订阅令牌</h3></div></div><div class="section-actions">%s</div></section></section>' % (host_view_attr, console_overview(nodes, state, clients, all_services_healthy, avg_latency), esc(host['hostname']), esc(host['uptime_text']), esc(host['load1']), esc(disk_text), esc(host['public_ip']), esc(host['os_name']), esc(host['cpu_text']), esc(host['memory_text']), esc(host['disk_text']), esc(host['kernel']), checked_class, checked_text, service_rows, feed_forms))

    parts.append('<div class="modal" id="mixed-forward-nodes-modal" role="dialog" aria-modal="true" aria-labelledby="mixed-forward-nodes-title" hidden><div class="modal-backdrop"></div><section class="modal-panel mixed-forward-modal-panel"><div class="modal-head"><div><h2 id="mixed-forward-nodes-title">订阅包含的节点</h2><p class="help" data-mixed-forward-count></p></div><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><div class="mixed-forward-node-list" data-mixed-forward-node-list></div><div class="actions"><button type="button" class="secondary" data-modal-close>关闭</button></div></section></div>')
    parts.append(
        ('<div class="modal" id="add-node-modal" role="dialog" aria-modal="true" aria-labelledby="add-node-title" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="add-node-title">添加节点</h2>'
         '<button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div>'
         '<form class="async-form" method="post" action="/node/add"><input type="hidden" name="csrf" value="%s">'
         '<input type="hidden" name="config" value="att"><input type="hidden" name="protocol" value="socks">'
         '<input type="hidden" name="address"><input type="hidden" name="port"><input type="hidden" name="username"><input type="hidden" name="password">'
         '<input type="hidden" name="uuid"><input type="hidden" name="server_name"><input type="hidden" name="public_key"><input type="hidden" name="short_id">'
         '<div class="form-error" role="alert" hidden></div>'
         '<label>上游节点数据</label><textarea name="node_input" rows="6" required placeholder="可粘贴 Proxy server / port / username / password 文本，或 socks5://、vless:// 链接"></textarea>'
         '<p class="help" data-node-parse-status>粘贴后自动识别；SOCKS5、HTTP、VLESS Reality 均可导入。</p>'
         '<label>用户</label><input name="user" required maxlength="80" autocomplete="off" placeholder="例如 客户A">'
         '<div class="field-grid"><div><label>开通日期</label><input name="activated_on" type="date" value="%s" required></div>'
         '<div><label>有效时长（天）</label><input name="duration_days" type="number" min="1" max="36500" value="30" required></div></div>'
         '<label>到期日期</label><input name="expires_on" type="date" readonly aria-readonly="true">'
         '<div class="actions"><button type="submit" disabled>检测通过后添加节点</button><button type="button" class="secondary" data-modal-close>取消</button></div>'
         '</form></section></div>') % (esc_csrf, esc(today)))
    parts.append(
        ('<div class="modal" id="edit-node-modal" role="dialog" aria-modal="true" aria-labelledby="edit-node-title" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="edit-node-title">编辑节点</h2>'
         '<button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div>'
         '<form class="async-form" method="post" action="/node/save"><input type="hidden" name="csrf" value="%s">'
         '<input type="hidden" name="config"><input type="hidden" name="tag"><div class="form-error" role="alert" hidden></div>'
         '<label>用户</label><input name="user" maxlength="80" autocomplete="off" placeholder="例如 客户A">'
         '<label>国家/地区</label><input name="country" maxlength="40" autocomplete="off" placeholder="例如 美国-加州">'
         '<div class="field-grid"><div><label>开通日期</label><input name="activated_on" type="date"></div>'
         '<div><label>有效时长（天）</label><input name="duration_days" type="number" min="1" max="36500"></div></div>'
         '<label>到期日期</label><input name="expires_on" type="date" readonly aria-readonly="true">'
         '<label>更新上游节点数据（可选）</label><textarea name="node_input" rows="5" placeholder="粘贴新的 Proxy server / port / username / password 文本，或 socks5://、vless:// 链接"></textarea>'
         '<p class="help" data-node-parse-status>留空将保留当前上游数据；粘贴新链接后会自动识别、检测并在保存时更新。</p>'
         '<p class="help">开通日期和有效时长需同时填写；到期日期会自动计算。粘贴数据检测失败时不能保存上游更新。</p>'
         '<div class="actions"><button type="submit">保存修改</button><button type="button" class="secondary" data-modal-close>取消</button></div>'
         '</form></section></div>') % esc_csrf)
    parts.append('<div class="modal" id="delete-node-modal" role="dialog" aria-modal="true" aria-labelledby="delete-node-title" aria-describedby="delete-dialog-description" hidden><div class="modal-backdrop"></div><section class="modal-panel delete-modal-panel"><div class="modal-head"><span class="delete-dialog-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 10v7m4-7v7"/></svg></span><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><h2 id="delete-node-title">删除确认</h2><p id="delete-dialog-description" class="delete-dialog-description">此操作无法撤销，请确认后继续。</p><div class="delete-dialog-target"><span data-delete-kind>删除对象</span><b data-delete-target></b></div><p class="delete-dialog-warning" data-delete-message></p><ul class="delete-list" data-delete-list hidden></ul><form class="console-delete-confirm-form"><div class="form-error" role="alert" tabindex="-1" hidden></div><p class="delete-dialog-progress" role="status" data-delete-progress></p><div class="actions"><button type="button" class="secondary" data-modal-close>暂不删除</button><button class="danger" type="submit">确认删除</button></div></form></section></div>')
    parts.append('<div class="modal" id="logout-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="logout-confirm-title" hidden><div class="modal-backdrop"></div><section class="modal-panel logout-confirm-panel"><div class="modal-head"><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><div class="logout-confirm-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 17l-5-5 5-5M5 12h10"></path><path d="M14 5h4v14h-4"></path></svg></div><h2 id="logout-confirm-title">确认退出登录？</h2><p>退出后需要重新输入登录凭据才能进入控制台。</p><form method="post" action="/logout"><input type="hidden" name="csrf" value="%s"><div class="actions"><button type="submit">确认退出</button><button type="button" class="secondary" data-modal-close>暂不退出</button></div></form></section></div>' % esc_csrf)
    parts.append('<div class="modal" id="change-password-modal" role="dialog" aria-modal="true" aria-labelledby="change-password-title" hidden><div class="modal-backdrop"></div><section class="modal-panel password-modal-panel"><div class="modal-head"><h2 id="change-password-title">修改账户密码</h2><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><p class="help">请验证当前密码后设置新密码。新密码至少 10 个字符。</p><form method="post" action="/account/password"><input type="hidden" name="csrf" value="%s"><label>当前密码</label><input type="password" name="current_password" autocomplete="current-password" required><label>新密码</label><input type="password" name="new_password" autocomplete="new-password" minlength="10" maxlength="256" required><label>确认新密码</label><input type="password" name="confirm_password" autocomplete="new-password" minlength="10" maxlength="256" required><div class="actions"><button type="button" class="secondary" data-modal-close>取消</button><button type="submit">保存新密码</button></div></form></section></div>' % esc_csrf)
    parts.append(('<div class="modal" id="edit-forward-title-modal" role="dialog" aria-modal="true" aria-labelledby="edit-forward-title" hidden><div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="edit-forward-title">修改订阅名称</h2><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><form class="async-form" method="post" action="/forward/title"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id"><div class="form-error" role="alert" hidden></div><label>订阅名称</label><input name="title" maxlength="80" required autocomplete="off"><p class="help">保存后，后台列表和客户端重新更新该订阅时显示的名称会同步为此名称；订阅地址不会改变。</p><div class="actions"><button type="submit">保存名称</button><button type="button" class="secondary" data-modal-close>取消</button></div></form></section></div>') % esc_csrf)
    parts.append('<div class="modal" id="forward-result-modal" role="dialog" aria-modal="true" aria-labelledby="forward-result-title" hidden><div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="forward-result-title">链接已创建</h2><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><div class="qr-result"><p><b data-forward-result-label></b><br><span class="muted">扫描二维码或复制链接导入客户端</span></p><img data-forward-qr-image width="280" height="280"><div class="qr-link-row"><textarea data-forward-result-value readonly spellcheck="false" aria-label="生成的链接"></textarea><button type="button" data-copy-value="">复制链接</button></div><div class="actions"><button type="button" class="secondary" data-modal-close>完成</button></div></div></section></div>')
    parts.append('</div></div>')
    return page(''.join(parts))


def xray_stats_query(pattern='user>>>'):
    try:
        result = subprocess.run([XRAY, 'api', 'statsquery', '--server=127.0.0.1:10085', '-pattern', pattern],
                                capture_output=True, text=True, timeout=10)
    except Exception:
        return {}
    if result.returncode:
        return {}
    stats = {}
    # Accept both protobuf text like "name: \"...\" value: 123" and JSON-ish output.
    for name, value in re.findall(r'name:\s*"([^"]+)"\s*value:\s*([0-9]+)', result.stdout):
        stats[name] = int(value)
    for name, value in re.findall(r'"name"\s*:\s*"([^"]+)"[^{}]*"value"\s*:\s*([0-9]+)', result.stdout):
        stats[name] = int(value)
    return stats


def update_traffic_stats():
    """Refresh per-forward traffic counters from Xray StatsService.

    Xray's StatsService counters are in-memory and reset when Xray restarts, so
    we store the last raw counter and add deltas to the persisted usage total.
    """
    stats = xray_stats_query('user>>>')
    if stats is None:
        return False
    changed = False
    with MUTEX:
        state = load_state()
        for item in state.get('forward_meta', {}).values():
            emails = item.get('emails')
            if not isinstance(emails, list):
                emails = [item.get('email')] if item.get('email') else []
            raw_upload = 0
            raw_download = 0
            for email in emails:
                raw_upload += int(stats.get('user>>>%s>>>traffic>>>uplink' % email, 0))
                raw_download += int(stats.get('user>>>%s>>>traffic>>>downlink' % email, 0))
            last_upload = int(item.get('traffic_last_raw_upload') or 0)
            last_download = int(item.get('traffic_last_raw_download') or 0)
            delta_upload = raw_upload - last_upload if raw_upload >= last_upload else raw_upload
            delta_download = raw_download - last_download if raw_download >= last_download else raw_download
            if delta_upload or delta_download or item.get('traffic_last_raw_upload') is None:
                item['quota_upload_bytes'] = int(item.get('quota_upload_bytes') or 0) + max(0, delta_upload)
                item['quota_download_bytes'] = int(item.get('quota_download_bytes') or 0) + max(0, delta_download)
                item['traffic_last_raw_upload'] = raw_upload
                item['traffic_last_raw_download'] = raw_download
                item['quota_checked_at'] = int(time.time())
                changed = True
        if changed:
            save_state(state)
    return changed

def forward_is_quota_exceeded(item):
    try:
        total = int(item.get('quota_total_bytes') or 0)
        used = int(item.get('quota_upload_bytes') or 0) + int(item.get('quota_download_bytes') or 0)
    except (TypeError, ValueError):
        return False
    return bool(total and used >= total)


def format_traffic_bytes(value):
    try:
        value = float(value or 0)
    except (TypeError, ValueError):
        value = 0
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024
        index += 1
    if index == 0:
        return '%dB' % value
    return ('%.2f%s' % (value, units[index])).rstrip('0').rstrip('.')


def forward_status(item):
    expire = item.get('quota_expire')
    try:
        expire = int(expire or 0)
    except (TypeError, ValueError):
        expire = 0
    if not expire:
        return {'class': 'neutral', 'text': '未设置', 'expires_on': ''}
    now = int(time.time())
    expires_on = item.get('quota_expires_on') or date.fromtimestamp(expire).isoformat()
    if forward_is_quota_exceeded(item):
        return {'class': 'bad', 'text': '流量用尽', 'expires_on': expires_on}
    if expire <= now:
        return {'class': 'bad', 'text': '已过期', 'expires_on': expires_on}
    days = int((expire - now) / 86400)
    if expire - now <= 7 * 86400:
        return {'class': 'warn', 'text': '快到期', 'expires_on': expires_on, 'days': days}
    return {'class': 'ok', 'text': '正常', 'expires_on': expires_on, 'days': days}


def forwarding_rows(state, clients):
    result = []
    client_by_key = {x['key']: x for x in clients}
    for ident, item in state.get('forward_meta', {}).items():
        mode = item.get('mode')
        node_count = 1
        if mode == 'external_subscription':
            value = item.get('url', '')
            name = 'FastClient 订阅'
            upstream = item.get('upstream', 'ran-us-residential')
        elif mode == 'socks':
            auth = ''
            if item.get('access_user'):
                auth = quote(item['access_user'], safe='') + ':' + quote(item.get('access_password', ''), safe='') + '@'
            value = 'socks5://%s%s:%s' % (auth, PUBLIC_HOST, item['listen_port'])
            name = 'SOCKS5'
            upstream = item.get('upstream', '')
        else:
            if mode == 'subscription':
                selected = item.get('subscription_nodes')
                node_count = len(selected) if isinstance(selected, list) and selected else 1
                value = 'https://%s:%d/sub/forward/%s' % (PUBLIC_HOST, PORT, item['subscription_token'])
                name = 'FastClient 订阅'
            else:
                row = client_by_key.get(item.get('client_key'))
                if not row:
                    continue
                value = row['link']
                name = 'VLESS'
            upstream = item.get('upstream', '')
        upload = int(item.get('quota_upload_bytes') or 0)
        download = int(item.get('quota_download_bytes') or 0)
        total = int(item.get('quota_total_bytes') or 0)
        status = forward_status(item)
        result.append({'id': ident, 'label': item.get('label', ident), 'mode': mode, 'mode_name': name,
                       'upstream': upstream, 'upstream_config': item.get('upstream_config', ''),
                       'upstream_count': node_count, 'subscription_nodes': item.get('subscription_nodes', []) if mode == 'subscription' else [], 'value': value, 'status': status,
                       'quota_total_display': format_traffic_bytes(total) if total else '未设置',
                       'quota_used_display': format_traffic_bytes(upload + download),
                       'expires_on': status.get('expires_on') or item.get('quota_expires_on') or '未设置'})
    return result


def curl_config_line(name, value):
    return '%s = "%s"\n' % (name, str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', ''))


def proxy_curl(proxy_url, username, password, url, metric=''):
    """Run curl through a proxy using a mode-0600 config file, never argv credentials."""
    fd, path = tempfile.mkstemp(prefix='.node-admin-curl-', text=True)
    try:
        lines = [curl_config_line('proxy', proxy_url), curl_config_line('max-time', '25'), curl_config_line('connect-timeout', '10'), curl_config_line('url', url)]
        if username:
            lines.append(curl_config_line('proxy-user', username + ':' + password))
        if metric:
            write_out = '%{time_starttransfer}' if metric == 'latency' else '%{speed_download}'
            lines.extend([curl_config_line('output', '/dev/null'), curl_config_line('write-out', write_out)])
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        os.chmod(path, 0o600)
        result = subprocess.run(['curl', '--config', path, '--silent', '--show-error'], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip()[-300:])
        return result.stdout.strip()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def free_loopback_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def upstream_tcp_latency(address, port):
    """Median TCP handshake time from this Japanese host to the upstream node."""
    samples = []
    last_error = None
    for _ in range(3):
        started = time.perf_counter()
        try:
            with socket.create_connection((address, int(port)), timeout=3):
                samples.append((time.perf_counter() - started) * 1000)
        except OSError as exc:
            last_error = exc
    if not samples:
        raise RuntimeError('本机连接节点失败：%s' % last_error)
    samples.sort()
    return max(1, int(samples[len(samples) // 2]))


def outbound_from_form(form, tag):
    """Build one managed Xray outbound from already-parsed upstream data."""
    address, port = validate_endpoint(form)
    protocol = form.get('protocol', '')
    if protocol == 'vless':
        node_uuid = form.get('uuid', '').strip()
        try:
            node_uuid = str(uuid.UUID(node_uuid))
        except ValueError:
            raise ValueError('VLESS UUID 格式无效')
        server_name = form.get('server_name', '').strip()
        public_key = form.get('public_key', '').strip()
        short_id = form.get('short_id', '').strip()
        if not server_name or not public_key or not short_id:
            raise ValueError('VLESS + REALITY 需要包含 Server Name、公钥和 Short ID')
        return {'tag': tag, 'protocol': 'vless', 'settings': {'address': address, 'port': port, 'id': node_uuid, 'encryption': 'none', 'flow': 'xtls-rprx-vision'}, 'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {'serverName': server_name, 'fingerprint': 'chrome', 'password': public_key, 'shortId': short_id}}}
    if protocol == 'http':
        return {'tag': tag, 'protocol': 'http', 'settings': {'servers': [{'address': address, 'port': port, 'users': [{'user': form.get('username', ''), 'pass': form.get('password', '')}]}]}}
    if protocol == 'socks':
        outbound = {'tag': tag, 'protocol': 'socks', 'settings': {'address': address, 'port': port}}
        if form.get('username'):
            outbound['settings']['user'] = form.get('username')
        if form.get('password'):
            outbound['settings']['pass'] = form.get('password')
        return outbound
    raise ValueError('仅支持 SOCKS5、HTTP 和 VLESS Reality 节点')


def probe_outbound(outbound):
    """Verify that an outbound can actually proxy traffic and return its TCP latency."""
    protocol = outbound.get('protocol')
    address, port = endpoint(outbound)
    if protocol not in MANAGED_PROTOCOLS or not address or not port:
        raise ValueError('该节点不支持检测')
    process = None
    temp_path = None
    try:
        latency_ms = upstream_tcp_latency(address, port)
        if protocol in ('socks', 'http'):
            username, password = outbound_proxy_auth(outbound)
            proxy_url = '%s://%s:%s' % ('socks5h' if protocol == 'socks' else 'http', address, port)
        else:
            local_port = free_loopback_port()
            fd, temp_path = tempfile.mkstemp(prefix='.node-admin-vless-', suffix='.json')
            payload = {'log': {'loglevel': 'warning'}, 'inbounds': [{'tag': 'test-socks', 'listen': '127.0.0.1', 'port': local_port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [outbound]}
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(payload, f)
            process = subprocess.Popen([XRAY, 'run', '-config', temp_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(20):
                try:
                    with socket.create_connection(('127.0.0.1', local_port), timeout=.2):
                        break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError('VLESS 测试通道启动失败')
                    time.sleep(.15)
            else:
                raise RuntimeError('VLESS 测试通道启动超时')
            username = password = ''
            proxy_url = 'socks5h://127.0.0.1:%s' % local_port
        exit_ip = proxy_curl(proxy_url, username, password, 'https://api.ipify.org')
        if not re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', exit_ip):
            raise RuntimeError('未获取到有效出口 IP')
        return {'checked_at': int(time.time()), 'latency_ms': latency_ms, 'exit_ip': exit_ip}
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def test_candidate_node(form):
    """Parse and test a candidate before it is allowed into a live Xray config."""
    apply_proxy_uri(form)
    return probe_outbound(outbound_from_form(form, 'candidate-test'))


def test_node(form):
    key, tag = parse_upstream(form.get('node', ''))
    cfg = CONFIGS[key]
    data = read_config(cfg)
    outbound = find_outbound(data, tag)
    if not outbound:
        raise ValueError('节点不存在')
    protocol = outbound.get('protocol')
    address, port = endpoint(outbound)
    if protocol not in MANAGED_PROTOCOLS or not address or not port:
        raise ValueError('该节点不支持检测')
    process = None
    temp_path = None
    try:
        connect_ms = upstream_tcp_latency(address, port)
        if protocol in ('socks', 'http'):
            username, password = outbound_proxy_auth(outbound)
            proxy_url = '%s://%s:%s' % ('socks5h' if protocol == 'socks' else 'http', address, port)
        else:
            # VLESS has no native curl transport; a temporary loopback SOCKS listener uses the exact outbound config.
            local_port = free_loopback_port()
            fd, temp_path = tempfile.mkstemp(prefix='.node-admin-vless-', suffix='.json')
            payload = {'log': {'loglevel': 'warning'}, 'inbounds': [{'tag': 'test-socks', 'listen': '127.0.0.1', 'port': local_port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [outbound]}
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(payload, f)
            process = subprocess.Popen([XRAY, 'run', '-config', temp_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(20):
                try:
                    with socket.create_connection(('127.0.0.1', local_port), timeout=.2):
                        break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError('VLESS 测试通道启动失败')
                    time.sleep(.15)
            else:
                raise RuntimeError('VLESS 测试通道启动超时')
            username = password = ''
            proxy_url = 'socks5h://127.0.0.1:%s' % local_port
        exit_ip = proxy_curl(proxy_url, username, password, 'https://api.ipify.org')
        if not re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', exit_ip):
            raise RuntimeError('未获取到有效出口 IP')
        started = time.monotonic()
        speed_value = proxy_curl(proxy_url, username, password, 'https://speed.cloudflare.com/__down?bytes=3000000', metric='speed')
        elapsed = int((time.monotonic() - started) * 1000)
        speed_mbps = round(float(speed_value) * 8 / 1000000, 2)
        reputation = subprocess.run(['curl', '-sS', '--max-time', '8', 'http://ip-api.com/json/%s?fields=status,country,isp,org,proxy,hosting,mobile' % exit_ip], capture_output=True, text=True, timeout=12)
        profile = json.loads(reputation.stdout) if reputation.returncode == 0 else {}
        signals = [name for name in ('proxy', 'hosting') if profile.get(name)]
        purity = '较高' if not signals else ('一般' if len(signals) == 1 else '较低')
        result = {'checked_at': int(time.time()), 'latency_ms': connect_ms, 'speed_mbps': speed_mbps, 'exit_ip': exit_ip,
                  'country': translate_country(profile.get('country', '未知')), 'isp': profile.get('isp', '')[:100],
                  'purity': purity, 'signals': signals, 'elapsed_ms': elapsed}
    except Exception as exc:
        result = {'checked_at': int(time.time()), 'error': str(exc)[:300]}
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    with MUTEX:
        state = load_state()
        state.setdefault('node_meta', {}).setdefault(key + '::' + tag, {})['test'] = result
        save_state(state)
    if result.get('error'):
        raise RuntimeError('检测失败：' + result['error'])
    return result


def test_all_nodes():
    targets = []
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        for outbound in data.get('outbounds', []):
            if outbound.get('tag') and outbound.get('protocol') in MANAGED_PROTOCOLS:
                targets.append({'node': key + '::' + outbound['tag']})
    completed = 0
    failed = 0
    # Parallel workers keep the page responsive enough even when a dead proxy
    # consumes its full connection timeout.
    with ThreadPoolExecutor(max_workers=min(3, max(1, len(targets)))) as pool:
        futures = [pool.submit(test_node, target) for target in targets]
        for future in as_completed(futures):
            try:
                future.result()
                completed += 1
            except Exception:
                failed += 1
    state = load_state()
    results = {}
    for target in targets:
        node_key = target['node']
        results[node_key] = state.get('node_meta', {}).get(node_key, {}).get('test', {'error': '未返回检测结果'})
    return completed, failed, results


def parse_upstream(value):
    if '::' not in value:
        raise ValueError('请选择可用上游节点')
    key, tag = value.split('::', 1)
    if key not in CONFIGS or not VALID_TAG.fullmatch(tag):
        raise ValueError('上游节点无效')
    data = read_config(CONFIGS[key])
    if not find_outbound(data, tag):
        raise ValueError('所选上游节点不存在')
    return key, tag


def add_user_route(data, cfg, email, outbound_tag):
    rules = data.setdefault('routing', {}).setdefault('rules', [])
    rule = {'type': 'field', 'inboundTag': [cfg['inbound']], 'user': [email], 'outboundTag': outbound_tag}
    # Xray evaluates routing rules top-to-bottom. Keep user-specific routes
    # ahead of the unqualified inbound fallback (the latter must remain last).
    fallback_index = next((index for index, item in enumerate(rules)
                           if item.get('inboundTag') == [cfg['inbound']]
                           and not item.get('user') and not item.get('network')), None)
    if fallback_index is None:
        rules.append(rule)
    else:
        rules.insert(fallback_index, rule)


def ensure_listen_port_available(port):
    if port in {PORT, *(cfg['entry'] for cfg in CONFIGS.values())}:
        raise ValueError('监听端口与管理面板或现有入口冲突')
    for cfg in CONFIGS.values():
        for inbound in read_config(cfg).get('inbounds', []):
            if inbound.get('port') == port:
                raise ValueError('监听端口已被 Xray 配置使用')
    probes = []
    try:
        for family, address in ((socket.AF_INET, ('0.0.0.0', port)), (socket.AF_INET6, ('::', port))):
            try:
                probe = socket.socket(family, socket.SOCK_STREAM)
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
                if family == socket.AF_INET6:
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                probe.bind(address)
                probes.append(probe)
            except OSError as exc:
                raise ValueError('监听端口已被系统占用：%s' % exc)
    finally:
        for probe in probes:
            probe.close()


def allocate_socks_port():
    """Choose an unused port from the firewall-backed SOCKS5 port pool."""
    size = SOCKS_PORT_END - SOCKS_PORT_START + 1
    start = secrets.randbelow(size)
    for offset in range(size):
        port = SOCKS_PORT_START + ((start + offset) % size)
        try:
            ensure_listen_port_available(port)
            return port
        except ValueError:
            continue
    raise RuntimeError('SOCKS5 自动端口池已满，请删除不用的转发后重试')


def default_forward_target():
    """Find the configured catch-all route used by the quick-create workflow."""
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        tag = fallback_tag(data, cfg)
        outbound = find_outbound(data, tag) if tag else None
        if outbound and (outbound.get('protocol') in MANAGED_PROTOCOLS or outbound.get('protocol') == 'freedom'):
            return key, tag
    raise ValueError('未配置可用默认出口，请先在节点管理中设置入口默认节点')


def parse_fastclient_subscription_nodes(form):
    raw = form.get('subscription_nodes', '')
    try:
        items = json.loads(raw)
    except (TypeError, ValueError):
        raise ValueError('请选择至少一个订阅节点')
    if not isinstance(items, list) or not 1 <= len(items) <= 12:
        raise ValueError('FastClient 订阅需要选择 1-12 个节点')
    result = []
    seen_upstreams = set()
    seen_labels = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('订阅节点格式无效')
        upstream = item.get('upstream', '')
        node_label = str(item.get('label', '')).strip()
        if not node_label or len(node_label) > 80 or '\n' in node_label or '\r' in node_label:
            raise ValueError('每个订阅节点都必须设置不超过 80 个字符的显示名称')
        config_key, tag = parse_upstream(upstream)
        canonical_upstream = config_key + '::' + tag
        normalized_label = node_label.casefold()
        if canonical_upstream in seen_upstreams:
            raise ValueError('同一个上游节点不能重复加入订阅')
        if normalized_label in seen_labels:
            raise ValueError('订阅内每个节点的显示名称必须唯一')
        seen_upstreams.add(canonical_upstream)
        seen_labels.add(normalized_label)
        result.append({'config': config_key, 'tag': tag, 'label': node_label})
    return result


def parse_forward_quota(form):
    quota_text = form.get('quota_total_gb', '').strip()
    expires_text = form.get('quota_expires_on', '').strip()
    if not quota_text or not expires_text:
        raise ValueError('请填写流量额度和到期日期')
    try:
        quota_gb = float(quota_text)
    except ValueError:
        raise ValueError('流量额度必须是数字')
    if not 0 < quota_gb <= 1024 * 1024:
        raise ValueError('流量额度必须大于 0 GB')
    try:
        expires = date.fromisoformat(expires_text)
    except ValueError:
        raise ValueError('到期日期格式无效')
    return {
        'quota_total_bytes': int(quota_gb * 1024 * 1024 * 1024),
        'quota_upload_bytes': 0,
        'quota_download_bytes': 0,
        'quota_expire': int(time.mktime(expires.timetuple())),
        'quota_expires_on': expires.isoformat(),
    }


def create_forward(form):
    label = form.get('label', '').strip()
    mode = form.get('mode', '')
    if not label or len(label) > 80 or '\n' in label or '\r' in label or mode not in ('socks', 'vless', 'subscription'):
        raise ValueError('转发名称或输出方式无效')
    quota_data = parse_forward_quota(form)
    if quota_data['quota_expire'] <= time.time():
        raise ValueError('到期日期必须晚于今天，避免转发创建后立即失效')
    subscription_nodes = []
    if mode == 'subscription':
        subscription_nodes = parse_fastclient_subscription_nodes(form)
        target_key = form.get('entry', '') or subscription_nodes[0]['config']
        if target_key not in CONFIGS or any(node['config'] != target_key for node in subscription_nodes):
            raise ValueError('同一条 FastClient 订阅只能选择同一入口下的节点')
        upstream_key, upstream_tag = subscription_nodes[0]['config'], subscription_nodes[0]['tag']
    else:
        requested_upstream = form.get('upstream', '').strip()
        if requested_upstream:
            upstream_key, upstream_tag = parse_upstream(requested_upstream)
            target_key = form.get('entry', '') or upstream_key
            if target_key != upstream_key:
                raise ValueError('转发入口必须与上游节点属于同一配置')
        else:
            target_key, upstream_tag = default_forward_target()
            upstream_key = target_key
    ident = secrets.token_hex(8)
    with MUTEX:
        cfg = CONFIGS[target_key]
        data = read_config(cfg)
        state = load_state()
        if mode == 'socks':
            listen_port = allocate_socks_port()
            user = 'socks-' + ident
            password = secrets.token_urlsafe(24)
            in_tag = 'forward-socks-' + ident
            settings = {'auth': 'password', 'accounts': [{'user': user, 'pass': password}]}
            data.setdefault('inbounds', []).append({'tag': in_tag, 'listen': '0.0.0.0', 'port': listen_port, 'protocol': 'socks', 'settings': settings})
            data.setdefault('routing', {}).setdefault('rules', []).append({'type': 'field', 'inboundTag': [in_tag], 'outboundTag': upstream_tag})
            state['forward_meta'][ident] = {'mode': 'socks', 'label': label, 'config': target_key,
                                            'upstream_config': upstream_key, 'upstream': upstream_tag,
                                            'inbound_tag': in_tag, 'listen_port': listen_port, 'access_user': user,
                                            'access_password': password, **quota_data}
        elif mode == 'subscription':
            inbound = find_inbound(data, cfg)
            if not inbound:
                raise ValueError('找不到指定入口')
            clients = inbound.setdefault('settings', {}).setdefault('clients', [])
            subscription_records = []
            client_keys = []
            emails = []
            for index, node in enumerate(subscription_nodes, start=1):
                email = 'forward-%s-%d' % (ident, index)
                client = {'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision', 'email': email}
                clients.append(client)
                add_user_route(data, cfg, email, node['tag'])
                client_key_value = client_key(target_key, client)
                state['client_meta'][client_key_value] = {'label': node['label'], 'created': int(time.time())}
                client_keys.append(client_key_value)
                emails.append(email)
                subscription_records.append({'config': node['config'], 'upstream': node['tag'], 'label': node['label'],
                                             'client_key': client_key_value, 'email': email})
            state['forward_meta'][ident] = {
                'mode': 'subscription', 'label': label, 'config': target_key,
                'upstream_config': upstream_key, 'upstream': upstream_tag,
                'upstreams': [node['tag'] for node in subscription_nodes],
                'client_key': client_keys[0], 'client_keys': client_keys,
                'email': emails[0], 'emails': emails,
                'subscription_nodes': subscription_records,
                'subscription_token': secrets.token_urlsafe(32), 'legacy_shared_feed': False,
                **quota_data,
            }
        else:
            inbound = find_inbound(data, cfg)
            if not inbound:
                raise ValueError('找不到指定入口')
            email = 'forward-' + ident
            client = {'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision', 'email': email}
            inbound.setdefault('settings', {}).setdefault('clients', []).append(client)
            add_user_route(data, cfg, email, upstream_tag)
            client_key_value = client_key(target_key, client)
            state['client_meta'][client_key_value] = {'label': label, 'created': int(time.time())}
            state['forward_meta'][ident] = {'mode': mode, 'label': label, 'config': target_key,
                                            'upstream_config': upstream_key, 'upstream': upstream_tag,
                                            'client_key': client_key_value, 'email': email, **quota_data}
        if mode == 'socks':
            value = 'socks5://%s:%s@%s:%s' % (quote(user, safe=''), quote(password, safe=''), PUBLIC_HOST, listen_port)
        elif mode == 'subscription':
            value = 'https://%s:%d/sub/forward/%s' % (PUBLIC_HOST, PORT, state['forward_meta'][ident]['subscription_token'])
        else:
            value = make_vless_link(cfg, find_inbound(data, cfg), client, label)
        commit_config_and_state(cfg, data, state)
        return {'id': ident, 'label': label, 'mode': mode, 'value': value}


def forward_dependency_rows(state, config_key, tag):
    """Return forwarding services that route through the selected upstream node."""
    mode_names = {'socks': 'SOCKS5', 'vless': 'VLESS', 'subscription': 'FastClient 订阅',
                  'external_subscription': 'FastClient 订阅'}
    result = []
    service_cache = {}
    for ident, item in state.get('forward_meta', {}).items():
        upstreams = item.get('upstreams')
        uses_tag = tag in upstreams if isinstance(upstreams, list) else item.get('upstream') == tag
        if not uses_tag:
            continue
        # New records retain the source config so identical tags on the two
        # entries cannot be mixed up. Legacy records predate this field; their
        # tag is still globally unique in normal configurations, so retain the
        # old tag-based behaviour for backwards compatibility.
        upstream_config = item.get('upstream_config')
        if upstream_config and upstream_config != config_key:
            continue
        target_config = item.get('config')
        target = CONFIGS.get(target_config, {})
        if target_config not in service_cache:
            try:
                service_cache[target_config] = service_state(target.get('service', ''))[0]
            except Exception:
                service_cache[target_config] = 'unknown'
        active_text = '运行中' if service_cache[target_config] == 'active' else ('未运行' if service_cache[target_config] else '状态未知')
        result.append({'id': ident, 'label': item.get('label') or ident,
                       'mode': mode_names.get(item.get('mode'), item.get('mode') or '未知'),
                       'entry': str(target.get('entry', target_config or '')),
                       'status': active_text,
                       'upstream': tag})
    return result



def forward_is_expired(item, now=None):
    expire = item.get('quota_expire')
    try:
        expire = int(expire or 0)
    except (TypeError, ValueError):
        expire = 0
    return bool(expire and expire <= int(now or time.time()))


def enforce_expired_forwards():
    """Remove expired forwarding credentials from Xray so cached clients stop working."""
    with MUTEX:
        state = load_state()
        expired = [(ident, item) for ident, item in list(state.get('forward_meta', {}).items())
                   if (forward_is_expired(item) or forward_is_quota_exceeded(item)) and not item.get('expired_enforced')]
        if not expired:
            return 0
        changed = {}
        for ident, item in expired:
            key = item.get('config')
            item['expired'] = forward_is_expired(item)
            item['quota_exceeded'] = forward_is_quota_exceeded(item)
            item['expired_enforced'] = True
            item['expired_enforced_at'] = int(time.time())
            if key not in CONFIGS:
                continue
            cfg = CONFIGS[key]
            data = changed.get(key)
            if data is None:
                data = read_config(cfg)
                changed[key] = data
            remove_forward_from_data(item, state, data, cfg)
        # Keep the management record, but remove Xray credentials/routes so the
        # cached client can no longer connect. The row remains visible for audit.
        if changed:
            for key, data in changed.items():
                commit_config_and_state(CONFIGS[key], data, state)
        else:
            save_state(state)
        return len(expired)


def expiration_worker():
    while True:
        try:
            update_traffic_stats()
            enforce_expired_forwards()
        except Exception as exc:
            print('expiration enforcement failed: %s' % exc, flush=True)
        time.sleep(60)

def remove_forward_from_data(item, state, data, cfg):
    # Legacy external subscriptions only point to a file served by FastClient.
    # Migrated subscriptions also own an internal Xray client, so that client
    # must be removed when the subscription itself is deleted.
    emails = item.get('emails')
    if not isinstance(emails, list):
        emails = [item.get('email')] if item.get('email') else []
    emails = [value for value in emails if isinstance(value, str) and value]
    client_keys = item.get('client_keys')
    if not isinstance(client_keys, list):
        client_keys = [item.get('client_key')] if item.get('client_key') else []
    if item.get('mode') == 'external_subscription' and not emails:
        return
    if item.get('mode') == 'socks':
        in_tag = item.get('inbound_tag')
        data['inbounds'] = [x for x in data.get('inbounds', []) if x.get('tag') != in_tag]
        data.setdefault('routing', {})['rules'] = [
            x for x in data.get('routing', {}).get('rules', []) if in_tag not in x.get('inboundTag', [])
        ]
        return
    inbound = find_inbound(data, cfg)
    if not inbound:
        raise ValueError('找不到入口配置')
    inbound['settings']['clients'] = [
        x for x in inbound.get('settings', {}).get('clients', []) if x.get('email') not in emails
    ]
    data.setdefault('routing', {})['rules'] = [
        x for x in data.get('routing', {}).get('rules', []) if not set(x.get('user', [])).intersection(emails)
    ]
    for key in client_keys:
        state['client_meta'].pop(key, None)


def delete_forward(form):
    ident = form.get('id', '')
    if form.get('confirm') != '1':
        raise ValueError('请确认删除转发')
    with MUTEX:
        state = load_state()
        item = state.get('forward_meta', {}).get(ident)
        if not item:
            raise ValueError('转发记录不存在')
        if item.get('mode') == 'external_subscription':
            revoke_external_subscription(item.get('url', ''), item.get('subscription_provider', 'fastclient'))
        if item.get('config') not in CONFIGS:
            raise ValueError('转发所属入口已下线，请先迁移记录')
        cfg = CONFIGS[item['config']]
        data = read_config(cfg)
        remove_forward_from_data(item, state, data, cfg)
        state['forward_meta'].pop(ident)
        if item.get('mode') == 'subscription' and item.get('legacy_shared_feed'):
            state['feeds'][item['config']] = secrets.token_urlsafe(32)
        commit_config_and_state(cfg, data, state)


def delete_node(form):
    """Delete an upstream node and all confirmed dependent forwards atomically."""
    config_key = form.get('config', '')
    tag = form.get('tag', '').strip()
    if config_key not in CONFIGS or not VALID_TAG.fullmatch(tag):
        raise ValueError('配置或节点标签无效')
    confirmed = form.get('confirm') == '1'
    node_key = config_key + '::' + tag
    with MUTEX:
        state = load_state()
        dependencies = forward_dependency_rows(state, config_key, tag)
        if not confirmed:
            return {'deleted': False, 'requires_confirmation': True, 'node': node_key, 'forwards': dependencies}
        cfg = CONFIGS[config_key]
        data = read_config(cfg)
        outbound = find_outbound(data, tag)
        if not outbound or outbound.get('protocol') not in MANAGED_PROTOCOLS:
            raise ValueError('节点不存在或不可删除')
        rotate_legacy_feeds = set()
        for dependency in dependencies:
            item = state.get('forward_meta', {}).get(dependency['id'])
            if item:
                if item.get('mode') == 'external_subscription':
                    revoke_external_subscription(item.get('url', ''), item.get('subscription_provider', 'fastclient'))
                remove_forward_from_data(item, state, data, cfg)
                if item.get('mode') == 'subscription' and item.get('legacy_shared_feed'):
                    rotate_legacy_feeds.add(item.get('config'))
                state['forward_meta'].pop(dependency['id'], None)
        for feed_config in rotate_legacy_feeds:
            if feed_config in CONFIGS:
                state['feeds'][feed_config] = secrets.token_urlsafe(32)
        was_fallback = fallback_tag(data, cfg) == tag
        data['outbounds'] = [x for x in data.get('outbounds', []) if x.get('tag') != tag]
        data.setdefault('routing', {})['rules'] = [x for x in data.get('routing', {}).get('rules', []) if x.get('outboundTag') != tag]
        if was_fallback and find_outbound(data, 'direct'):
            set_fallback(data, cfg, 'direct')
        state['node_meta'].pop(node_key, None)
        commit_config_and_state(cfg, data, state)
        return {'deleted': True, 'requires_confirmation': False, 'node': node_key, 'forwards': dependencies}


def prune_login_failures(now):
    stale = []
    for ip, attempts in LOGIN_FAILURES.items():
        recent = [stamp for stamp in attempts if now - stamp < LOGIN_WINDOW]
        if recent:
            LOGIN_FAILURES[ip] = recent
        else:
            stale.append(ip)
    for ip in stale:
        LOGIN_FAILURES.pop(ip, None)
    if len(LOGIN_FAILURES) > MAX_LOGIN_IPS:
        oldest = sorted(LOGIN_FAILURES, key=lambda ip: LOGIN_FAILURES[ip][-1])
        for ip in oldest[:len(LOGIN_FAILURES) - MAX_LOGIN_IPS]:
            LOGIN_FAILURES.pop(ip, None)


class Handler(BaseHTTPRequestHandler):
    server_version = 'NodeAdmin'
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        line = fmt % args
        line = re.sub(r'(/sub/)[^ ?"]+', r'\1<redacted>', line)
        print('%s - %s' % (self.address_string(), line), flush=True)

    def common_headers(self):
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Strict-Transport-Security', 'max-age=31536000')

    def send_html(self, body, status=200):
        payload = body.encode()
        self.send_response(status)
        self.common_headers()
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_bytes(self, payload, content_type='text/plain; charset=utf-8', status=200):
        self.send_response(status)
        self.common_headers()
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_fastclient_subscription(self, payload, title, userinfo=None):
        self.send_response(200)
        self.common_headers()
        self.send_header('Content-Type', 'text/yaml; charset=utf-8')
        self.send_header('Content-Disposition', "attachment; filename*=UTF-8''" + quote(title, safe=''))
        self.send_header('Subscription-Userinfo', userinfo or 'upload=0; download=0; total=536870912000; expire=0')
        self.send_header('Profile-Title', 'base64:' + base64.b64encode(title.encode('utf-8')).decode('ascii'))
        self.send_header('Profile-Update-Interval', '24')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, data, status=200):
        if getattr(self, '_audit_action', None):
            operations.record(self._audit_action, status < 400 and data.get('ok', True), self.client_address[0])
            self._audit_action = None
        payload = json.dumps(data, ensure_ascii=False).encode()
        self.send_bytes(payload, 'application/json; charset=utf-8', status)

    def redirect(self, location, cookies=None):
        payload = ('<html><head><meta http-equiv="refresh" content="0;url=%s"></head><body><a href="%s">继续</a></body></html>' % (html.escape(location, quote=True), html.escape(location, quote=True))).encode()
        self.send_response(303)
        self.common_headers()
        self.send_header('Location', location)
        for cookie in cookies or []:
            self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(payload)
    def redirect_dashboard(self, session, flash='', error=''):
        """After a mutation, return to the page from which the form was submitted."""
        session.pop('flash', None)
        session.pop('error', None)
        if flash:
            session['flash'] = flash
        if error:
            session['error'] = error
        if 'application/json' in self.headers.get('Accept', ''):
            self.send_json({'ok': not bool(error), 'error': error, 'message': flash}, 400 if error else 200)
            return
        if getattr(self, '_audit_action', None):
            operations.record(self._audit_action, not bool(error), self.client_address[0])
            self._audit_action = None
        referer_path = urlsplit(self.headers.get('Referer', '')).path
        destination = referer_path if referer_path in PATH_VIEWS else '/nodes'
        body = ('<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=%s">' % esc(destination)).encode()
        self.send_response(200)
        self.common_headers()
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def cookie_sid(self):
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie', ''))
        except Exception:
            return ''
        morsel = jar.get('node_admin_session')
        return morsel.value if morsel else ''

    def session(self):
        sid = self.cookie_sid()
        if not sid:
            return None
        item = SESSIONS.get(sid)
        if not item:
            state = load_state()
            saved = state.get('sessions', {}).get(sid)
            if saved and saved.get('expires', 0) > time.time():
                item = {'csrf': saved['csrf'], 'expires': saved['expires'], 'persistent': True, 'persisted_at': time.time()}
                SESSIONS[sid] = item
        now = time.time()
        if not item or item['expires'] < now:
            SESSIONS.pop(sid, None)
            remove_persistent_session(sid)
            return None
        item['sid'] = sid
        if item.get('persistent'):
            item['expires'] = now + 30 * 86400
            if now - item.get('persisted_at', 0) >= 3600:
                save_persistent_session(sid, item['csrf'], item['expires'])
                item['persisted_at'] = now
        else:
            item['expires'] = now + 8 * 3600
        return item

    def require_session(self):
        item = self.session()
        if not item:
            if 'application/json' in self.headers.get('Accept', ''):
                self.send_json({'ok': False, 'error': '登录已过期，请重新登录'}, 401)
            else:
                self.redirect('/login')
            return None
        return item

    def form(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length < 0 or length > 65536 or self.headers.get('Transfer-Encoding'):
            raise ValueError('请求过大')
        raw = self.rfile.read(length).decode()
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def do_GET(self):
        self._audit_action = None
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == '/healthz':
            self.send_bytes(b'ok\n')
            return
        if path == '/boot.js':
            self.send_bytes(BOOT_JS.encode(), 'application/javascript; charset=utf-8')
            return
        if path == '/app.js':
            self.send_bytes(APP_JS.encode(), 'application/javascript; charset=utf-8')
            return
        if path == '/ops/status':
            item = self.require_session()
            if item:
                self.send_json({'ok': True, 'events': operations.events(), 'backups': operations.backups()})
            return
        if path == '/host/status':
            item = self.require_session()
            if item:
                try:
                    self.send_json({'ok': True, **host_snapshot()})
                except Exception as exc:
                    self.send_json({'ok': False, 'error': str(exc)}, 500)
            return
        if path == '/forward/qr':
            item = self.require_session()
            if not item:
                return
            ident = parse_qs(parsed.query).get('id', [''])[0]
            if not ident or len(ident) > 160:
                self.send_bytes(b'not found\n', status=404)
                return
            state = load_state()
            row = next((record for record in forwarding_rows(state, client_rows(state)) if record['id'] == ident), None)
            if not row or not row.get('value'):
                self.send_bytes(b'not found\n', status=404)
                return
            self.send_bytes(make_qr_svg(row['value']), 'image/svg+xml; charset=utf-8')
            return
        if path.startswith('/sub/forward/'):
            enforce_expired_forwards()
            state = load_state()
            token = path[len('/sub/forward/'):]
            item = next((record for record in state['forward_meta'].values()
                         if record.get('mode') == 'subscription'
                         and isinstance(record.get('subscription_token'), str)
                         and hmac.compare_digest(record['subscription_token'], token)), None)
            if not item or '/' in token:
                self.send_bytes(b'not found\n', status=404)
                return
            payload = make_fastclient_forward_subscription(state, item)
            if payload is None:
                self.send_bytes(b'not found\n', status=404)
                return
            title = item.get('label') or 'FastClient 订阅'
            self.send_fastclient_subscription(payload, title, subscription_userinfo(state, item))
            return
        if path.startswith('/sub/'):
            state = load_state()
            token = path[len('/sub/'):]
            scope = next((x for x, value in state['feeds'].items() if hmac.compare_digest(value, token)), None)
            if not scope:
                self.send_bytes(b'not found\n', status=404)
                return
            query = parse_qs(parsed.query)
            output_format = query.get('format', ['base64'])[0]
            if output_format not in ('base64', 'vless', 'raw'):
                self.send_bytes(b'unsupported format\n', status=400)
                return
            payload = make_subscription(state, scope, output_format)
            self.send_bytes(payload, 'text/plain; charset=utf-8')
            return
        if path == '/login':
            if self.session():
                self.redirect('/')
            else:
                self.send_html(login_page())
            return
        if path == '/' or path in PATH_VIEWS:
            enforce_expired_forwards()
            item = self.require_session()
            if item:
                try:
                    if path == '/':
                        self.redirect('/nodes')
                        return
                    flash = item.pop('flash', '')
                    error = item.pop('error', '')
                    self.send_html(dashboard(item['csrf'], flash=flash, error=error, active_view=PATH_VIEWS[path]))
                except Exception as exc:
                    self.send_html(page('<div class="flash error">读取配置失败：%s</div>' % esc(exc)), 500)
            return
        self.send_bytes(b'Not Found\n', status=404)

    def do_POST(self):
        self._audit_action = None
        path = urlsplit(self.path).path
        try:
            form = self.form()
        except Exception as exc:
            self.send_bytes((str(exc) + '\n').encode(), status=400)
            return
        if path == '/login':
            ip = self.client_address[0]
            now = time.time()
            with MUTEX:
                prune_login_failures(now)
                attempts = LOGIN_FAILURES.setdefault(ip, [])
                if len(attempts) >= LOGIN_LIMIT:
                    self.send_html(login_page('登录失败次数过多，请稍后重试'), 429)
                    return
            username = load_auth().get('username', 'admin')
            if hmac.compare_digest(form.get('username', ''), username) and verify_password(form.get('password', '')):
                sid = secrets.token_urlsafe(32)
                csrf = secrets.token_urlsafe(24)
                persistent = form.get('remember') == '1'
                duration = 30 * 86400 if persistent else 8 * 3600
                SESSIONS[sid] = {'csrf': csrf, 'expires': now + duration, 'persistent': persistent, 'persisted_at': now}
                if persistent:
                    save_persistent_session(sid, csrf, now + duration)
                with MUTEX:
                    LOGIN_FAILURES.pop(ip, None)
                cookie = 'node_admin_session=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict' % (sid, duration)
                self.redirect('/nodes', [cookie])
            else:
                with MUTEX:
                    LOGIN_FAILURES.setdefault(ip, []).append(now)
                self.send_html(login_page('账户或密码错误'), 401)
            return
        session = self.require_session()
        if not session:
            return
        wants_json = 'application/json' in self.headers.get('Accept', '')
        if not hmac.compare_digest(form.get('csrf', ''), session['csrf']):
            if wants_json:
                self.send_json({'ok': False, 'error': 'CSRF 校验失败，请刷新页面'}, 403)
            else:
                self.send_html(page('<div class="flash error">CSRF 校验失败，请刷新页面</div>'), 403)
            return
        self._audit_action = path if path in operations.ACTIONS else None
        if path == '/ops/backup':
            try:
                with MUTEX:
                    name = operations.create_backup(CONFIGS, STATE_FILE, str(APP_DIR))
                self.send_json({'ok': True, 'message': '备份已安全保存至服务器（保留最近 10 份）', 'name': name})
            except Exception:
                self.send_json({'ok': False, 'error': '备份失败，请检查磁盘和目录权限'}, 500)
            return
        if path == '/ops/sessions/revoke':
            revoke_other_sessions(session.get('sid', ''))
            self.send_json({'ok': True, 'message': '其他登录会话已退出，当前会话保留'})
            return
        if path == '/logout':
            sid = session.get('sid', '')
            SESSIONS.pop(sid, None)
            remove_persistent_session(sid)
            cookie = 'node_admin_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'
            self.redirect('/login', [cookie])
            return
        if path == '/account/password':
            try:
                change_admin_password(form.get('current_password', ''), form.get('new_password', ''), form.get('confirm_password', ''))
            except ValueError as exc:
                self.redirect_dashboard(session, error=str(exc))
            except Exception:
                self.redirect_dashboard(session, error='密码保存失败，请稍后重试')
            else:
                revoke_other_sessions(session.get('sid', ''))
                self.redirect_dashboard(session, flash='账户密码已更新，其他登录会话已退出')
            return
        if path == '/feeds/rotate':
            scope = form.get('scope', '')
            if scope not in ('all', *CONFIGS):
                self.send_json({'ok': False, 'error': '未知订阅范围'}, 400) if wants_json else self.redirect_dashboard(session, error='未知订阅范围')
                return
            state = load_state()
            state['feeds'][scope] = secrets.token_urlsafe(32)
            save_state(state)
            self.redirect_dashboard(session, flash='订阅令牌已轮换，旧链接立即失效。')
            return
        if path == '/node/validate':
            try:
                parsed = parse_node_input(form.get('node_input', ''))
                address, port = validate_endpoint(parsed)
                country = geo_lookup(address) or ''
            except Exception as exc:
                self.send_json({'ok': False, 'error': str(exc)}, 400)
                return
            try:
                result = test_candidate_node({'node_input': form.get('node_input', '')})
                self.send_json({'ok': True, 'valid': True, 'protocol': parsed['protocol'], 'address': address,
                                'port': port, 'country': country, **result})
            except Exception as exc:
                self.send_json({'ok': True, 'valid': False, 'protocol': parsed['protocol'], 'address': address,
                                'port': port, 'country': country, 'error': str(exc)[:300]})
            return
        try:
            if path == '/node/save':
                result = save_node(form)
                metadata_only = result.startswith('仅更新')
                message = '节点已保存。' + (result if metadata_only else '配置校验和服务健康检查通过。备份：' + result)
                if wants_json:
                    self.send_json({'ok': True, 'message': message, 'metadata_only': metadata_only,
                                    'node': {'user': form.get('user', '').strip()[:80],
                                             'country': form.get('country', '').strip()[:40]}})
                else:
                    self.redirect_dashboard(session, flash=message)
                return
            if path == '/node/delete':
                result = delete_node(form)
                if wants_json:
                    if result.get('requires_confirmation'):
                        self.send_json({'ok': False, **result}, 409)
                    else:
                        self.send_json({'ok': True, **result})
                elif result.get('requires_confirmation'):
                    names = '、'.join(item['label'] for item in result.get('forwards', []))
                    self.redirect_dashboard(session, error='节点仍被以下转发服务使用：%s；请确认清理后再删除。' % names)
                else:
                    self.redirect_dashboard(session, flash='节点已删除，关联转发配置已清理并重启服务。')
                return
            if path == '/node/default':
                set_default_node(form)
                self.redirect_dashboard(session, flash='入口默认上游已切换。')
                return
            if path == '/node/test':
                try:
                    result = test_node(form)
                except Exception as exc:
                    if wants_json:
                        node_key = form.get('node', '')
                        stored = load_state().get('node_meta', {}).get(node_key, {}).get('test', {'error': str(exc)})
                        self.send_json({'ok': False, 'error': str(exc), 'result': stored}, 400)
                        return
                    raise
                if wants_json:
                    self.send_json({'ok': True, 'node': form.get('node', ''), 'result': result})
                else:
                    self.redirect_dashboard(session, flash='检测完成：延迟 %sms，速度 %s Mbps，出口 %s。' % (result['latency_ms'], result['speed_mbps'], result['exit_ip']))
                return
            if path == '/node/test-all':
                completed, failed, results = test_all_nodes()
                if wants_json:
                    self.send_json({'ok': failed == 0, 'completed': completed, 'failed': failed, 'results': results})
                else:
                    self.redirect_dashboard(session, flash='全部节点检测完成：%d 个成功，%d 个失败。' % (completed, failed))
                return
            if path == '/node/add':
                add_node(form)
                self.redirect_dashboard(session, flash='上游节点已添加；如需接管入口流量，请点击该节点的“设为入口默认”。')
                return
            if path == '/forward/create':
                result = create_forward(form)
                if wants_json:
                    self.send_json({'ok': True, 'forward': result})
                else:
                    self.redirect_dashboard(session, flash='转发已创建并启用。')
                return
            if path == '/forward/title':
                title = rename_external_forward(form)
                if wants_json:
                    self.send_json({'ok': True, 'title': title})
                else:
                    self.redirect_dashboard(session, flash='订阅名称已同步。')
                return
            if path == '/forward/delete':
                delete_forward(form)
                self.redirect_dashboard(session, flash='转发已删除，配置已校验并重启服务。')
                return
            if path == '/client/add':
                add_client(form)
                self.redirect_dashboard(session, flash='VLESS 客户端已生成并启用。')
                return
            if path == '/client/toggle':
                toggle_client(form)
                self.redirect_dashboard(session, flash='客户端链接状态已更新。')
                return
            if path == '/client/delete':
                delete_client(form)
                self.redirect_dashboard(session, flash='客户端已永久删除。')
                return
            if path == '/service/restart':
                key = form.get('config')
                if key not in CONFIGS:
                    raise ValueError('未知配置')
                result = subprocess.run(['systemctl', 'restart', CONFIGS[key]['service']], capture_output=True, text=True, timeout=25)
                if result.returncode:
                    raise RuntimeError((result.stderr or result.stdout).strip()[-800:])
                wait_service_healthy(CONFIGS[key])
                self.redirect_dashboard(session, flash='服务已重启并通过健康检查。')
                return
            self.send_bytes(b'Not Found\n', status=404)
        except Exception as exc:
            if wants_json:
                self.send_json({'ok': False, 'error': str(exc)}, 400)
            else:
                self.redirect_dashboard(session, error=str(exc))


def validate_endpoint(form):
    address = form.get('address', '').strip()
    if not VALID_ADDRESS.fullmatch(address):
        raise ValueError('上游地址格式无效')
    try:
        port = int(form.get('port', ''))
    except ValueError:
        raise ValueError('端口必须是数字')
    if not 1 <= port <= 65535:
        raise ValueError('端口必须在 1-65535')
    return address, port


def generate_node_tag(address, existing_tags):
    """Create an internal-only Xray tag; users never need to enter or see it."""
    base = re.sub(r'[^A-Za-z0-9]+', '-', address).strip('-').lower() or 'upstream'
    base = base[:64].rstrip('-') or 'upstream'
    for _ in range(20):
        candidate = 'node-%s-%s' % (base, secrets.token_hex(4))
        if candidate not in existing_tags:
            return candidate
    raise RuntimeError('无法生成唯一的内部节点标识')


def lifecycle_from_form(form, existing=None, required=False):
    """Validate the business dates kept with a managed upstream node."""
    existing = existing or {}
    activated_on = form.get('activated_on', '').strip() or str(existing.get('activated_on', '')).strip()
    duration_text = form.get('duration_days', '').strip()
    duration_value = duration_text or existing.get('duration_days', '')
    if not activated_on and not duration_value:
        if required:
            raise ValueError('请填写开通日期和有效时长')
        return {}
    if not activated_on or not duration_value:
        raise ValueError('开通日期和有效时长需要同时填写')
    try:
        opened = date.fromisoformat(activated_on)
    except ValueError:
        raise ValueError('开通日期格式无效')
    try:
        duration_days = int(duration_value)
    except (TypeError, ValueError):
        raise ValueError('有效时长必须是天数')
    if not 1 <= duration_days <= 36500:
        raise ValueError('有效时长必须在 1-36500 天之间')
    return {'activated_on': opened.isoformat(), 'duration_days': duration_days,
            'expires_on': (opened + timedelta(days=duration_days)).isoformat()}


def node_input_value(raw, labels):
    for label in labels:
        match = re.search(r'(?im)^\s*' + label + r'\s*[:：]\s*(.+?)\s*$', raw)
        if match:
            return match.group(1).strip().strip('\"\'')
    return ''


def parse_node_input(raw):
    """Parse a URI or the labelled proxy-generator text without exposing credentials."""
    raw = (raw or '').strip()
    if not raw:
        raise ValueError('请粘贴上游节点数据')
    link = re.search(r'(?i)(?:socks5?|shcks5|vless|http)://[^\s<>\"\']+', raw)
    if link:
        uri = re.sub(r'(?i)^shcks5://', 'socks5://', link.group(0))
        try:
            parsed = urlsplit(uri)
            port = parsed.port
        except ValueError:
            raise ValueError('节点链接中的端口无效')
        scheme = parsed.scheme.lower()
        if scheme not in ('socks', 'socks5', 'vless', 'http') or not parsed.hostname or not port:
            raise ValueError('节点链接必须是有效的 SOCKS5、HTTP 或 VLESS 链接')
        result = {'address': parsed.hostname, 'port': str(port)}
        if scheme in ('socks', 'socks5', 'http'):
            result.update({'protocol': 'socks' if scheme.startswith('socks') else 'http',
                           'username': unquote(parsed.username or ''), 'password': unquote(parsed.password or '')})
            return result
        query = parse_qs(parsed.query)
        result.update({'protocol': 'vless', 'uuid': unquote(parsed.username or ''),
                       'server_name': query.get('sni', query.get('serverName', ['']))[0],
                       'public_key': query.get('pbk', query.get('publicKey', ['']))[0],
                       'short_id': query.get('sid', query.get('shortId', ['']))[0]})
        return result

    address = node_input_value(raw, (r'proxy\s*server', r'server', r'host', r'地址', r'代理地址'))
    port = node_input_value(raw, (r'port', r'端口'))
    if ' / ' in address:
        address = address.rsplit(' / ', 1)[-1].strip()
    if not address or not port:
        raise ValueError('未识别到 Proxy server 和 Port；请粘贴完整链接或包含这两个字段的文本')
    protocol_value = node_input_value(raw, (r'protocol', r'type', r'类型')).lower()
    protocol = 'http' if protocol_value in ('http', 'https') else 'socks'
    return {'protocol': protocol, 'address': address, 'port': port,
            'username': node_input_value(raw, (r'username', r'user(?:name)?', r'用户名', r'账号')),
            'password': node_input_value(raw, (r'password', r'pass(?:word)?', r'密码'))}


def apply_proxy_uri(form):
    """Apply a parsed node link or proxy-generator block to the Xray fields."""
    raw = form.get('node_input', '').strip() or form.get('proxy_uri', '').strip()
    if not raw:
        return {}
    parsed = parse_node_input(raw)
    for key, value in parsed.items():
        if key in ('protocol', 'address', 'port') or value or not form.get(key):
            form[key] = value
    return parsed


def save_node(form):
    key = form.get('config')
    tag = form.get('tag', '').strip()
    if key not in CONFIGS or not VALID_TAG.fullmatch(tag):
        raise ValueError('配置或节点标签无效')
    candidate_result = None
    replacement_outbound = None
    if form.get('node_input', '').strip():
        apply_proxy_uri(form)
        candidate_result = test_candidate_node(form)
        replacement_outbound = outbound_from_form(form, tag)
    with MUTEX:
        cfg = CONFIGS[key]
        data = read_config(cfg)
        original_config = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        outbound = find_outbound(data, tag)
        if not outbound or outbound.get('protocol') not in MANAGED_PROTOCOLS:
            raise ValueError('节点不存在或协议不可编辑')
        if replacement_outbound is not None:
            position = next(index for index, item in enumerate(data.get('outbounds', [])) if item is outbound)
            data['outbounds'][position] = replacement_outbound
            outbound = replacement_outbound
        user = form.get('user', '').strip()[:80]
        state = load_state()
        node_key = key + '::' + tag
        meta = state.setdefault('node_meta', {}).setdefault(node_key, {})
        country = form.get('country', '').strip()[:40]
        if replacement_outbound is not None:
            address, _ = endpoint(replacement_outbound)
            meta['country'] = country or geo_lookup(address) or meta.get('country', '未标注')
            meta['test'] = candidate_result
        elif country:
            meta['country'] = country
        if 'user' in form:
            meta['user'] = user
        lifecycle = lifecycle_from_form(form, meta)
        if lifecycle:
            meta.update(lifecycle)
        current_config = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        if current_config == original_config:
            save_state(state)
            return '仅更新面板元数据，无需重启入口'
        _, _, backup = commit_config_and_state(cfg, data, state)
        return backup


def set_default_node(form):
    key = form.get('config'); tag = form.get('tag', '')
    if key not in CONFIGS:
        raise ValueError('未知配置')
    with MUTEX:
        cfg = CONFIGS[key]; data = read_config(cfg)
        if not find_outbound(data, tag):
            raise ValueError('节点不存在')
        set_fallback(data, cfg, tag)
        write_config_json(cfg, data)


def add_node(form):
    apply_proxy_uri(form)
    key = form.get('config')
    protocol = form.get('protocol', '')
    if key not in CONFIGS or protocol not in MANAGED_PROTOCOLS:
        raise ValueError('配置或协议无效')
    address, port = validate_endpoint(form)
    user = form.get('user', '').strip()[:80]
    if not user:
        raise ValueError('请填写用户')
    lifecycle = lifecycle_from_form(form, required=True)
    country = geo_lookup(address) or '未标注'
    candidate_result = test_candidate_node(form)
    with MUTEX:
        cfg = CONFIGS[key]; data = read_config(cfg)
        existing_tags = {str(item.get('tag', '')) for item in data.get('outbounds', [])}
        tag = generate_node_tag(address, existing_tags)
        outbound = outbound_from_form(form, tag)
        if find_outbound(data, tag):
            raise ValueError('节点标签已存在')
        data.setdefault('outbounds', []).insert(0, outbound)
        state = load_state()
        metadata = {'country': country, 'user': user, 'test': candidate_result}
        metadata.update(lifecycle)
        state.setdefault('node_meta', {})[key + '::' + tag] = metadata
        commit_config_and_state(cfg, data, state)


def add_client(form):
    key = form.get('config')
    label = form.get('label', '').strip()
    if key not in CONFIGS or not label or len(label) > 80 or '\n' in label or '\r' in label:
        raise ValueError('入口或链接名称无效')
    with MUTEX:
        cfg = CONFIGS[key]; data = read_config(cfg); inbound = find_inbound(data, cfg)
        if not inbound:
            raise ValueError('找不到入口配置')
        existing = {x.get('email') for x in inbound.get('settings', {}).get('clients', [])}
        if label in existing:
            raise ValueError('链接名称已存在')
        client = {'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision', 'email': label}
        inbound.setdefault('settings', {}).setdefault('clients', []).append(client)
        state = load_state()
        ckey = client_key(key, client)
        state.setdefault('client_meta', {})[ckey] = {'label': label, 'created': int(time.time())}
        commit_config_and_state(cfg, data, state)


def find_client_by_key(state, key):
    if '::' not in key:
        raise ValueError('客户端标识无效')
    config_key, identity = key.split('::', 1)
    if config_key not in CONFIGS:
        raise ValueError('未知入口配置')
    cfg = CONFIGS[config_key]; data = read_config(cfg); inbound = find_inbound(data, cfg)
    if not inbound:
        raise ValueError('找不到入口配置')
    for client in inbound.get('settings', {}).get('clients', []):
        if client_key(config_key, client) == key:
            return config_key, cfg, data, inbound, client, True
    disabled = state.get('disabled_clients', {}).get(key)
    if disabled and disabled.get('config') == config_key:
        return config_key, cfg, data, inbound, disabled.get('client', {}), False
    raise ValueError('客户端不存在')


def toggle_client(form):
    key = form.get('key', '')
    with MUTEX:
        state = load_state(); config_key, cfg, data, inbound, client, enabled = find_client_by_key(state, key)
        old_state = json.loads(json.dumps(state))
        old_bytes = open(cfg['path'], 'rb').read(); old_mode = stat.S_IMODE(os.stat(cfg['path']).st_mode)
        if enabled:
            inbound['settings']['clients'] = [x for x in inbound.get('settings', {}).get('clients', []) if client_key(config_key, x) != key]
            state['disabled_clients'][key] = {'config': config_key, 'inbound': cfg['inbound'], 'client': client}
        else:
            inbound.setdefault('settings', {}).setdefault('clients', []).append(client)
            state['disabled_clients'].pop(key, None)
        try:
            write_config_json(cfg, data)
            save_state(state)
        except Exception:
            restore_config(cfg, old_bytes, old_mode)
            save_state(old_state)
            raise


def delete_client(form):
    key = form.get('key', '')
    with MUTEX:
        state = load_state(); config_key, cfg, data, inbound, client, enabled = find_client_by_key(state, key)
        old_state = json.loads(json.dumps(state))
        if enabled:
            old_bytes = open(cfg['path'], 'rb').read(); old_mode = stat.S_IMODE(os.stat(cfg['path']).st_mode)
            inbound['settings']['clients'] = [x for x in inbound.get('settings', {}).get('clients', []) if client_key(config_key, x) != key]
            state['client_meta'].pop(key, None); state['disabled_clients'].pop(key, None)
            try:
                write_config_json(cfg, data); save_state(state)
            except Exception:
                restore_config(cfg, old_bytes, old_mode); save_state(old_state); raise
        else:
            state['client_meta'].pop(key, None); state['disabled_clients'].pop(key, None); save_state(state)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(MAX_REQUEST_THREADS)
        super().__init__(*args, **kwargs)

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(5)
        try:
            sock = self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
            sock.do_handshake()
            sock.settimeout(30)
            return sock, addr
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            raise

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(timeout=1):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def main():
    if os.geteuid() != 0:
        raise SystemExit('must run as root')
    if not PUBLIC_HOST:
        raise SystemExit('PUBLIC_HOST must be configured')
    load_state()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    server = BoundedThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    server.ssl_context = context
    update_traffic_stats()
    enforce_expired_forwards()
    threading.Thread(target=expiration_worker, daemon=True).start()
    print('node-admin listening on https://0.0.0.0:%d' % PORT, flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
