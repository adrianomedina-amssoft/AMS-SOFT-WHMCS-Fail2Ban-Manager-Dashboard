import runpy
import unittest
from pathlib import Path
from fail2ban.server.failregex import FailRegex

ROOT = Path(__file__).resolve().parents[1]
H = runpy.run_path(str(ROOT/'setup/amsfb-admin'))


class SessionLfi(unittest.TestCase):
    def hit(self, target, ip='198.51.100.77', status=404, protocol='1.1',
            groups=None, enabled=True, tail='"-" "fixture"'):
        text = H['sensitive_filter'](groups or ['session_lfi_probe'], enabled)
        pattern = H['parse'](text).get('Definition', 'failregex').replace('%%', '%')
        r = FailRegex(pattern)
        r.search([(f'{ip} - - [] "GET {target} HTTP/{protocol}" {status} 10 {tail}', '', '')])
        return r.getHost() if r.hasMatched() else None

    def test_closed_payload_and_real_peer(self):
        for ip in ('198.51.100.77', '2001:db8::77'):
            for sep in ('/', '%2f', '%2F', '%252f'):
                target = '/vuln.php?page='+sep+'tmp'+sep+'sessions'+sep+'sess_fixture-01_a'
                for status in (200, 301, 302, 403, 404, 421, 500):
                    for protocol in ('1.0', '1.1', '2'):
                        self.assertEqual(self.hit(target, ip, status, protocol,
                            tail='"203.0.113.44" "[client 203.0.113.55:7]"'), ip)

    def test_negatives_and_independence(self):
        for target in ('/', '/vuln.php', '/vuln.php?page=home', '/vuln.php?page=/tmp/sessions/sess_',
                       '/vuln.php?page=/tmp/sessions/sess_a.txt', '/vuln.php?page=/tmp/sessions/sess_a/extra',
                       '/vuln.php?page=/tmp/sessions/sess_a&next=home', '/vuln.php?page=/docs/manual',
                       '/index.php?page=/tmp/sessions/sess_a', '/docs/vuln.php?page=/tmp/sessions/sess_a',
                       '/vuln.php?note=/tmp/sessions/sess_a', '/vuln.php?page=/tmp/sessions/sess_'+'a'*129):
            self.assertIsNone(self.hit(target, tail='"/vuln.php?page=/tmp/sessions/sess_a" "scanner"'))
        target = '/vuln.php?page=/tmp/sessions/sess_a'
        self.assertIsNone(self.hit(target, groups=['env']))
        self.assertIsNone(self.hit(target, enabled=False))

    def test_validated_native_signature(self):
        line = '198.51.100.77 - - [27/Oct/2026:10:14:25 -0300] "GET /vuln.php?page=/tmp/sessions/sess_fixture HTTP/1.1" 404 10 "-" "fixture"'
        H['validate_filter'](H['sensitive_filter'](['session_lfi_probe']), [line])


if __name__ == '__main__':
    unittest.main()
