import json
import runpy
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
H = runpy.run_path(str(ROOT / 'setup/amsfb-admin'))

class QueryProbe(unittest.TestCase):
    def test_php_helper_classification_parity(self):
        paths = ["/index.php?rp=/password/reset'", "/index.php?rp=%2Fpassword%2Freset%27",
                 "/index.php?rp=%252Fpassword%252Freset%2527", "/index.php?rp=/password/reset",
                 "/index.php?name=O'Reilly", "/index.php?search=test'", "/index.php?rp=/name''",
                 "/index.php", "/index.php?rp=/bad%00path'", "/index.php?rp=%25252Freset%252527"]
        lines = [f'198.51.100.77 - - [25/Oct/2026:00:00:00 -0300] "{method} {p} HTTP/1.1" {status} 10 "-" "fixture"'
                 for p in paths for method in ('GET','HEAD','POST') for status in (200,301,403,404,421,500,503)]
        result = subprocess.run(['php',str(ROOT/'tests/query_probe.php'),'--json'],
                                input=json.dumps(lines),text=True,capture_output=True,check=True)
        php = json.loads(result.stdout)
        with patch.dict(H['non_offensive_line'].__globals__, {'normal_paths':lambda:['/','/index.php']}):
            for line, expected in zip(lines,php):
                with self.subTest(line=line):
                    self.assertEqual(H['query_probe_route'](line),expected['route'])
                    self.assertEqual(H['non_offensive_line'](line),expected['normal'])

    def test_headers_and_500_alone_not_candidates(self):
        for line in ['198.51.100.77 - - [25/Oct/2026:00:00:00 -0300] "GET /index.php HTTP/1.1" 500 10 "-" "/index.php?rp=/reset\'"',
                     '[Sun Oct 25 00:00:00 2026] [php:notice] [client 198.51.100.77:1234] /index.php?rp=/reset\'']:
            self.assertIsNone(H['query_probe_route'](line))

    def test_real_native_validator_accepts_exact_query_not_status_rule(self):
        evidence = [f'198.51.100.77 - - [25/Oct/2026:00:00:0{i} -0300] "GET /index.php?rp=/password/reset\' HTTP/1.1" 500 10 "-" "fixture"' for i in range(5)]
        pattern = r"""^<HOST> - \S+ \[\s*\] "GET /index\.php\?rp=/password/reset' HTTP/1\.1" 500 \S+ "[^"]*" "[^"]*"$"""
        with patch.dict(H['non_offensive_line'].__globals__, {'normal_paths':lambda:['/','/index.php']}):
            H['validate_filter']('[Definition]\nfailregex = '+pattern+'\nignoreregex =\n', evidence)
            for bad in [r'^<HOST> .* 500 .*', r'^<HOST> .*fixture.*']:
                with self.assertRaises(H['FilterValidationError']):
                    H['validate_filter']('[Definition]\nfailregex = '+bad+'\nignoreregex =\n', evidence)

if __name__ == '__main__':
    unittest.main()
