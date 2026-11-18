import runpy
import unittest
from pathlib import Path
from fail2ban.server.failregex import FailRegex

H = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'setup/amsfb-admin'))
TARGET = '/boaform/adminformLogout//boaform/admin/login.asp'

def expression(groups=None, enabled=True):
    return FailRegex(H['parse'](H['sensitive_filter'](groups or ['boaform_probe'], enabled)).get('Definition', 'failregex').replace('%%', '%'))

def hit(regex, target=TARGET, ip='198.51.100.77', method='GET', status=404, version='1.0', tail='"-" "-"'):
    line = f'{ip} - - [] "{method} {target} HTTP/{version}" {status} 437 {tail}'
    regex.search([(line, '', '')])
    return regex.getHost() if regex.hasMatched() else None

class BoaformTests(unittest.TestCase):
    def test_exact_positive_peer_status_and_query(self):
        regex = expression()
        for ip in ('198.51.100.77', '2001:db8::77'):
            for status in (200, 301, 302, 403, 404, 421, 500):
                for version in ('1.0', '1.1', '2.0'):
                    for suffix in ('', '?x=1'):
                        self.assertEqual(hit(regex, TARGET + suffix, ip=ip, status=status, version=version), ip)

    def test_closed_target_and_method(self):
        regex = expression()
        for target in ('/', '/login', '/admin-custom/login.php', '/boaform/', TARGET.lower(), TARGET+'/', TARGET+'.bak',
                       '/prefix'+TARGET, '/'+TARGET, TARGET.replace('//', '/'), TARGET.replace('login.asp', 'loginXasp'),
                       TARGET.replace('/', '%2f', 1), '/index.php?next='+TARGET):
            self.assertIsNone(hit(regex, target))
        for method in ('HEAD', 'POST', 'OPTIONS', 'XGET', 'get'):
            self.assertIsNone(hit(regex, method=method))

    def test_headers_do_not_select_target_or_peer(self):
        regex = expression()
        tail = f'"{TARGET}" "GET {TARGET} HTTP/1.0 [client 203.0.113.9]"'
        self.assertIsNone(hit(regex, '/clientarea.php', tail=tail))
        self.assertEqual(hit(regex, ip='2001:db8::77', tail=tail), '2001:db8::77')
        regex.search([(f'[] [client 198.51.100.77:123] denied {TARGET}', '', '')])
        self.assertFalse(regex.hasMatched())

    def test_opt_out_and_other_groups(self):
        self.assertIsNone(hit(expression(enabled=False)))
        self.assertIsNone(hit(expression(['env'])))
        self.assertEqual(hit(expression(list(H['PROBE_GROUPS']))), '198.51.100.77')

if __name__ == '__main__':
    unittest.main()
