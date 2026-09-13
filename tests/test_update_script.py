"""Exercise the real update flow with disposable files and fake system services."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class UpdateScriptTests(unittest.TestCase):
    def run_update(self, fail_at):
        bash = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')
        if not bash or not Path(bash).exists():
            self.skipTest('bash unavailable')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('source/relay_admin', 'live', 'bin', 'config', 'backups'):
                (root / name).mkdir(parents=True, exist_ok=True)
            names = ('app.py', 'operations.py', 'console.css', 'console.js', 'delete-dialog.js', 'login.js')
            for name in names:
                (root / 'live' / name).write_text('old', encoding='utf-8')
                (root / 'source/relay_admin' / name).write_text('new', encoding='utf-8')
            (root / 'config/admin.json').write_text('{}', encoding='utf-8')
            (root / 'config/config.json').write_text('{}', encoding='utf-8')
            script = (Path(__file__).parents[1] / 'update.sh').read_text(encoding='utf-8')
            script = script.replace("[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }", ':')
            for old, new in {'/opt/node-admin': root / 'live', '/etc/node-admin': root / 'config',
                    '/etc/xray-att-relay': root / 'config', '/var/backups/node-admin': root / 'backups',
                    '/run/relay-admin-update.lock': root / 'update.lock'}.items():
                script = script.replace(old, new.as_posix())
            # All service interactions are mocked; only copies/traps run for real.
            bin_path = (root / 'bin').as_posix()
            if os.name == 'nt':
                bin_path = '/' + bin_path[0].lower() + bin_path[2:]
            script = script.replace('IFS=$\'\\n\\t\'', 'IFS=$\'\\n\\t\'\nexport PATH="' + bin_path + ':$PATH"')
            (root / 'source/update.sh').write_text(script, encoding='utf-8', newline='\n')
            mocks = {'python3': 'exit 0', 'flock': 'exit 0', 'sleep': 'exit 0',
                'curl': '[[ "$FAIL_AT" == health ]] && exit 22\necho ok',
                'systemctl': 'if [[ "$1" == restart && "$FAIL_AT" == restart && ! -f "$MARKER" ]]; then touch "$MARKER"; exit 1; fi\nexit 0'}
            if os.name == 'nt':
                mocks['install'] = 'if [[ "$1" == -d ]]; then mkdir -p "${@: -1}"; else cp "${@: -2:1}" "${@: -1}"; fi'
            for name, body in mocks.items():
                path = root / 'bin' / name
                path.write_text('#!/usr/bin/env bash\n' + body + '\n', encoding='utf-8', newline='\n')
                path.chmod(0o755)
            (root / 'source/selftest.sh').write_text('[[ "$FAIL_AT" != selftest ]]\n', encoding='utf-8')
            env = dict(os.environ, FAIL_AT=fail_at, MARKER=(root / 'marker').as_posix())
            result = subprocess.run([bash, (root / 'source/update.sh').as_posix()], env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode == 0, not fail_at, result.stdout + result.stderr)
            self.assertTrue(list((root / 'backups').glob('app-update-*/app.py')), result.stdout + result.stderr)
            for name in names:
                self.assertEqual((root / 'live' / name).read_text(encoding='utf-8'), 'old' if fail_at else 'new', result.stderr)

    def test_restart_failure_rolls_back(self):
        self.run_update('restart')

    def test_health_failure_rolls_back(self):
        self.run_update('health')

    def test_selftest_failure_rolls_back(self):
        self.run_update('selftest')

    def test_success_keeps_new_files(self):
        self.run_update('')
