import io, json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import app, operations

class BackendTests(unittest.TestCase):
    def handler(self):
        h=object.__new__(app.Handler)
        h.headers={}; h.client_address=('127.0.0.1',1234); h._audit_action=None
        return h

    def test_form_limits(self):
        for length in ('-1','65537','invalid'):
            h=self.handler();h.headers={'Content-Length':length};h.rfile=io.BytesIO(b'')
            with self.assertRaises(ValueError): h.form()
        h=self.handler();h.headers={'Content-Length':'3'};h.rfile=io.BytesIO(b'a=b')
        self.assertEqual(h.form(),{'a':'b'})

    def test_mutation_error_is_not_success(self):
        h=self.handler();h.headers={'Accept':'application/json'};out=[]
        h.send_json=lambda data,status=200:out.append((data,status))
        h.redirect_dashboard({},error='rejected')
        self.assertEqual(out[0][1],400);self.assertFalse(out[0][0]['ok'])

    def test_api_auth_is_json(self):
        h=self.handler();h.headers={'Accept':'application/json'};h.session=lambda:None;out=[]
        h.send_json=lambda data,status=200:out.append((data,status))
        self.assertIsNone(h.require_session());self.assertEqual(out[0][1],401)

    def test_session_revocation_preserves_current(self):
        sessions={'mine':{},'other':{}};state={'sessions':{'mine':{},'other':{}}};saved=[]
        with patch.object(app,'SESSIONS',sessions),patch.object(app,'load_state',return_value=state),patch.object(app,'save_state',side_effect=saved.append):
            app.revoke_other_sessions('mine')
        self.assertEqual(list(sessions),['mine']);self.assertEqual(list(saved[0]['sessions']),['mine'])

    def test_backup_and_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'source').mkdir();(p/'source'/'app.py').write_text('test');(p/'config').mkdir();(p/'config'/'state.json').write_text('{}')
            (p/'backups').mkdir();(p/'backups'/'pre-upgrade-preserved.tar.gz').write_text('keep')
            with patch.object(operations,'BACKUPS',str(p/'backups')):
                for _ in range(12):operations.create_backup({},str(p/'config'/'state.json'),str(p/'source'))
                self.assertEqual(len(operations.backups()),10)
                self.assertTrue((p/'backups'/'pre-upgrade-preserved.tar.gz').exists())
                import tarfile
                with tarfile.open(p/'backups'/operations.backups()[0]['name']) as tar:
                    self.assertTrue(any(n.endswith('source/app.py') for n in tar.getnames()))
                if os.name == 'posix':
                    self.assertEqual((p/'backups'/operations.backups()[0]['name']).stat().st_mode & 0o777,0o600)

    def test_audit_allowlist(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(operations,'AUDIT',directory+'/audit.jsonl'):
            operations.record('/sub/secret-password',True)
            operations.record('/node/add',True,'127.0.0.1')
            self.assertEqual(len(operations.events()),1)
            self.assertNotIn('secret-password',Path(operations.AUDIT).read_text())

    def test_create_rejects_expired_date(self):
        with self.assertRaisesRegex(ValueError,'晚于今天'):
            app.create_forward({'label':'test','mode':'socks','quota_total_gb':'500','quota_expires_on':'2000-01-01'})

    def test_quota_rejects_invalid_values(self):
        for value in ['NaN','inf','-1','0','1048577']:
            with self.assertRaises(ValueError):
                app.parse_forward_quota({'quota_total_gb':value,'quota_expires_on':'2030-01-01'})

    @patch.object(app, 'CONFIGS', {})
    @patch.object(app, 'load_state', return_value={'feeds': {}, 'forward_meta': {}, 'node_meta': {}})
    @patch.object(app, 'host_snapshot', return_value=dict.fromkeys(
        ('hostname', 'uptime_text', 'load1', 'public_ip', 'os_name', 'cpu_text', 'memory_text', 'disk_text', 'kernel'), 'test') | {'services': {}, 'disk_used_percent': None})
    def test_html_renders(self, *_):
        body=app.dashboard('test-csrf')
        self.assertIn('中转控制台',body);self.assertIn('console-stats',body)
        self.assertNotIn('CONSOLE_EXTENSION',app.APP_JS)
        self.assertIn('role="alert"',app.dashboard('test',error='<script>'))
        self.assertIn('&lt;script&gt;',app.dashboard('test',error='<script>'))

if __name__=='__main__':unittest.main(verbosity=2)
