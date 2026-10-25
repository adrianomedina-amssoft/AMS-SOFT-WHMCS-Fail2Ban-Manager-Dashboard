import runpy
import unittest
from datetime import datetime, timezone
from pathlib import Path

H = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'setup/amsfb-admin'))


class ExtendedApplications(unittest.TestCase):
    def test_native_proof_normalization_ipv4_ipv6(self):
        paths = ['/login.do', '/showLogin.cc', '/sugar_version.json', '/solr/']
        pattern = r'^<HOST> - \S+ \[\s*\] "GET (?:/login\.do|/showLogin\.cc|/sugar_version\.json|/solr/) HTTP/1\.1" 404 \d+'
        for ip in ['198.18.74.2', '2001:db8::742']:
            stamp = datetime.now(timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
            evidence = [f'{ip} - - [{stamp}] "GET {p} HTTP/1.1" 404 10 "-" "fixture"' for p in paths]
            result = H['normalize_evidence_filter']({'patterns': [pattern], 'evidence': evidence})
            self.assertTrue(result['success'])
            self.assertEqual(len(result['matched_sha256']), 4)

    def test_native_validator_rejects_missing_positive_branch(self):
        stamp = datetime.now(timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        evidence = [f'198.18.74.2 - - [{stamp}] "GET /login.do HTTP/1.1" 404 10 "-" "fixture"']
        patterns = [r'^<HOST> - \S+ \[\s*\] "GET /login\.do HTTP/1\.1" 404 \d+',
                    r'^<HOST> - \S+ \[\s*\] "GET /solr/ HTTP/1\.1" 404 \d+']
        with self.assertRaises(ValueError):
            H['normalize_evidence_filter']({'patterns': patterns, 'evidence': evidence})


if __name__ == '__main__':
    unittest.main()
