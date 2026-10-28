import runpy
import unittest
import socket
from unittest.mock import patch
from pathlib import Path
from fail2ban.server.filter import Filter
from fail2ban.server.ipdns import DNSUtils, IPAddr

ROOT = Path(__file__).resolve().parents[1]
H = runpy.run_path(str(ROOT/'setup/amsfb-admin'))
R = runpy.run_path(str(ROOT/'scripts/legacy_peer_repair.py'))


def numeric_only(value):
    try:
        return {IPAddr(x[4][0]) for x in socket.getaddrinfo(value, None, socket.AF_INET, 0,
                socket.IPPROTO_TCP, socket.AI_NUMERICHOST)}
    except socket.gaierror:
        return set()


class LegacyPeer(unittest.TestCase):
    def captures(self, pattern, line):
        f = Filter(None, useDns='warn')
        f.addFailRegex(pattern)
        with patch.object(DNSUtils, 'dnsToIp', side_effect=numeric_only):
            return [str(x[1]) for x in f.findFailure((line, '', ''), 1793140000)]

    def test_reproduction_and_repaired_peer(self):
        for family, path, agent, pattern in [
            ('api-probe', '/actuator/health', 'zgrab', r'^.*<HOST>.*"GET /actuator/.*HTTP/.*".*".*zgrab.*".*$'),
            ('badbots', '/', 'ShapBot', r'^.*<HOST> .* "(HEAD|GET) .* HTTP/1\.\d" (200|404) .* "-" ".*ShapBot.*"$'),
            ('cart-probe', '/cart.php?a=add&domain=transfer', 'meta-webindexer', r'^.*<HOST> -.*\[.*\] "GET /cart\.php\?a=add&domain=transfer.*meta-webindexer.*".*$'),
            ('cms-probe', '/custom_page_template.php?cmsid=1', 'fixture', r'^.*<HOST> .* "GET /custom_page_template\.php\?.* HTTP/.*"'),
            ('whmcs-probe', r'/cart.php?a=add&domain=transfer\xC2\xA4', 'fixture', r'^.*<HOST>.*"GET /cart\.php\?a=add&domain=transfer.*\\xC2\\xA4.*$'),
        ]:
            old = '[Definition]\nfailregex = '+pattern+'\nignoreregex =\n'
            new = H['parse'](R['repair']('amsfb-apache-'+family, old)).get('Definition', 'failregex')
            line = f'198.51.100.77 - - [] "GET {path} HTTP/1.0" 200 10 "-" "{agent}"'
            self.assertIn('0.0.0.7', self.captures(pattern, line))
            for ip in ('198.51.100.77', '2001:db8::77'):
                for protocol in ('1.0', '1.1'):
                    example = f'{ip} - - [] "GET {path} HTTP/{protocol}" 200 10 "-" "{agent} 203.0.113.44"'
                    self.assertEqual(self.captures(new, example), [ip])
                    self.assertEqual(self.captures(new, 'prefix '+example), [])
            with self.assertRaises(H['FilterValidationError']) as err:
                H['validate_filter'](old, [line])
            self.assertEqual(err.exception.code, 'filter_peer')

    def test_error_header_and_scope(self):
        pattern = r'^.* \[client <HOST>:\d+\] "GET /query\?q=.*" 404'
        old = '[Definition]\nfailregex = '+pattern+'\nignoreregex =\n'
        new = H['parse'](R['repair']('amsfb-apache-api-probe', old)).get('Definition', 'failregex')
        for ip in ('198.51.100.77', '2001:db8::77'):
            line = f'[] [core:error] [pid 123:tid 45] [client {ip}:54321] "GET /query?q=1 HTTP/1.1" 404'
            self.assertEqual(self.captures(new, line), [ip])
            self.assertEqual(self.captures(new, '198.51.100.44 - - [] "GET / HTTP/1.1" 404 10 "-" "'+line+'"'), [])
        with self.assertRaises(ValueError):
            R['repair']('sshd', old)


if __name__ == '__main__':
    unittest.main()
