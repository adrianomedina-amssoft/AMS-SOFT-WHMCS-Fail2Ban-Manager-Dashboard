import json
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

H = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'setup/amsfb-admin'))


class NormalRoutes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='amsfb-routes-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.globals = H['normal_paths'].__globals__
        self.overrides = patch.dict(self.globals, {'ROOT': self.root, 'BACKUPS': self.root / 'backup'})
        self.overrides.start()
        self.addCleanup(self.overrides.stop)

    @staticmethod
    def line(target, status=200):
        return f'198.51.100.77 - - [17/Oct/2026:15:00:00 -0300] "GET {target} HTTP/1.1" {status} 10 "-" "scanner"'

    def test_sync_literal_and_backup_without_native_actions(self):
        with patch.dict(self.globals, {'run': lambda args: self.fail('Must not invoke daemon/firewall')}):
            first = H['sync_normal_paths']({'paths': ['/', '/graylog', '/graylog']})
            self.assertTrue(first['changed'])
            self.assertEqual(H['normal_paths'](), ['/', '/graylog'])
            self.assertFalse(H['sync_normal_paths']({'paths': ['/', '/graylog']})['changed'])
            H['sync_normal_paths']({'paths': ['/graylog']})
            self.assertEqual(len(list((self.root / 'backup').glob('*.bakp'))), 1)

    def test_invalid_payload_never_written(self):
        for bad in [[], {'paths': '/graylog'}, {'paths': ['/graylog'], 'extra': 1},
                    {'paths': ['/x?y']}, {'paths': ['/.*']}, {'paths': ['/x'] * 51},
                    {'paths': ['/a\n']}, {'paths': [None]}, {'paths': ['/' * 201]}]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                H['sync_normal_paths'](bad)
        self.assertFalse((self.root / 'amsfb-normal-paths.json').exists())

    def test_normal_path_does_not_hide_sensitive_children_or_query(self):
        H['sync_normal_paths']({'paths': ['/graylog']})
        for status in (200, 301, 403, 404):
            self.assertTrue(H['non_offensive_line'](self.line('/graylog', status)))
        self.assertFalse(H['non_offensive_line'](self.line('/graylog-unrelated')))
        for path in ['/graylog/.git/config', '/graylog/%2eenv', '/graylog?file=../../etc/passwd']:
            self.assertFalse(H['non_offensive_line'](self.line(path)))

    def test_native_validator_rejects_exact_normal_target(self):
        H['sync_normal_paths']({'paths': ['/graylog']})
        regex = r'^<HOST> - \S+ \[\s*\] "GET /graylog HTTP/1\.1" 200 \S+'
        with self.assertRaisesRegex(ValueError, 'signals'):
            H['validate_filter']('[Definition]\nfailregex = ' + regex + '\nignoreregex =\n',
                                 [self.line('/graylog')])

    def test_corrupted_catalogue_fails_closed(self):
        (self.root / 'amsfb-normal-paths.json').write_text('not json')
        with self.assertRaises(ValueError):
            H['non_offensive_line'](self.line('/graylog'))
        # Offensive evidence remains offensive independently of normal catalogue.
        self.assertFalse(H['non_offensive_line'](self.line('/graylog/.git/config')))


if __name__ == '__main__':
    unittest.main()
