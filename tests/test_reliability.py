import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class ReliabilityTests(unittest.TestCase):
    def test_exit_probe_falls_back(self):
        with patch.object(app, 'proxy_curl', side_effect=[RuntimeError('timeout'), 'ip=8.8.8.8\n']) as curl:
            self.assertEqual(app.probe_proxy_exit_ip('socks5h://test', '', ''), '8.8.8.8')
            self.assertEqual(curl.call_count, 2)

    def test_invalid_exit_responses_fail_closed(self):
        with patch.object(app, 'proxy_curl', side_effect=['<html>error</html>', 'ip=127.0.0.1', '999.1.1.1']):
            with self.assertRaisesRegex(RuntimeError, '多个检测地址'):
                app.probe_proxy_exit_ip('socks5h://test', '', '')

    def test_optional_failures_do_not_mark_proxy_offline(self):
        with patch.object(app, 'proxy_curl', side_effect=RuntimeError('timeout')), patch.object(
                app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'not json')):
            result = app.probe_optional_metrics('socks5h://test', '', '', '8.8.8.8')
        self.assertNotIn('error', result)
        self.assertIsNone(result['speed_mbps'])
        self.assertEqual(result['purity'], '未知')
        self.assertEqual(len(result['warnings']), 2)

    def test_missing_reputation_is_not_high_purity(self):
        with patch.object(app, 'proxy_curl', return_value='1000'), patch.object(
                app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"status":"success"}')):
            self.assertEqual(app.probe_optional_metrics('', '', '', '8.8.8.8')['purity'], '未知')

    def test_restart_timeout_restores_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            original = b'{"outbounds": []}'
            path.write_bytes(original)
            cfg = {'path': str(path), 'service': 'test.service'}
            success = subprocess.CompletedProcess([], 0, '', '')
            with patch.object(app, 'BACKUP_DIR', directory), patch.object(app, 'wait_service_healthy'), patch.object(
                    app.subprocess, 'run', side_effect=[success, subprocess.TimeoutExpired('systemctl', 25), success]):
                with self.assertRaisesRegex(RuntimeError, '已自动回滚'):
                    app.write_config_json(cfg, {'outbounds': [{'tag': 'new'}]})
            self.assertEqual(path.read_bytes(), original)

    def test_failed_recovery_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text('{}', encoding='utf-8')
            with patch.object(app, 'BACKUP_DIR', directory), patch.object(app.subprocess, 'run', side_effect=[
                    subprocess.CompletedProcess([], 0, '', ''), subprocess.TimeoutExpired('systemctl', 25),
                    subprocess.TimeoutExpired('systemctl', 25)]):
                with self.assertRaisesRegex(RuntimeError, '服务恢复失败'):
                    app.write_config_json({'path': str(path), 'service': 'test.service'}, {})

    def test_restart_with_larger_counters_counts_all_new_bytes(self):
        state = {'forward_meta': {'node': {'traffic_generation': 'old', 'traffic_last_raw_upload': 100,
            'traffic_last_raw_download': 0, 'quota_upload_bytes': 100}}}
        with patch.object(app, 'stats_service_generation', return_value='new'), patch.object(
                app, 'xray_stats_query', return_value={'user>>>client>>>traffic>>>uplink': 150}), patch.object(
                app, 'forward_stats_keys', return_value=['client']), patch.object(app, 'load_state', return_value=state), patch.object(app, 'save_state'):
            app.update_traffic_stats()
        self.assertEqual(state['forward_meta']['node']['quota_upload_bytes'], 250)

    def test_restart_during_sampling_discards_ambiguous_sample(self):
        with patch.object(app, 'stats_service_generation', side_effect=['old', 'new']), patch.object(
                app, 'xray_stats_query', return_value={}), patch.object(app, 'save_state') as save:
            self.assertFalse(app.update_traffic_stats())
            save.assert_not_called()

    def test_commit_keeps_latest_traffic_and_edited_metadata(self):
        state = {'forward_meta': {'node': {'label': 'edited', 'quota_upload_bytes': 10}}}
        latest = {'forward_meta': {'node': {'label': 'old', 'quota_upload_bytes': 25, 'traffic_generation': 'run'}}}
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'STATE_FILE', directory + '/state.json'), patch.object(
                app, 'update_traffic_stats'), patch.object(app, 'load_state', return_value=latest), patch.object(
                app, 'write_config_json', return_value=(b'{}', 0o600, 'backup')), patch.object(app, 'save_state') as save:
            app.commit_config_and_state({}, {}, state)
        item = save.call_args.args[0]['forward_meta']['node']
        self.assertEqual(item['label'], 'edited')
        self.assertEqual(item['quota_upload_bytes'], 25)
        self.assertEqual(item['traffic_generation'], 'run')


if __name__ == '__main__':
    unittest.main()
