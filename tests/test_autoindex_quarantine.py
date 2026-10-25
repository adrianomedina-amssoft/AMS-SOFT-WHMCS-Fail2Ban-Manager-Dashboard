import runpy
import unittest
from pathlib import Path
from fail2ban.server.failregex import FailRegex

ROOT = Path(__file__).resolve().parents[1]
H = runpy.run_path(str(ROOT/'setup/amsfb-admin'))

class AutoindexQuarantine(unittest.TestCase):
    def test_closed_two_jail_override_without_action_or_lifetime_changes(self):
        cfg=H['parse']((ROOT/'setup/fail2ban/jail.autoindex-quarantine.local').read_text())
        self.assertEqual(set(cfg.sections()),{'apache-autoindex-dir','apache-autoindex-ah01276'})
        for jail in cfg.sections():
            self.assertEqual(set(cfg.options(jail)),{'failregex','usedns'})
            self.assertEqual(cfg.get(jail,'usedns'),'no')
            r=FailRegex(cfg.get(jail,'failregex'))
            for ip in ['198.51.100.77','2001:db8::77']:
                for line in [f'[] [autoindex:error] [pid 123] [client {ip}:54321] AH01276: Cannot serve directory /var/www/html/: No matching DirectoryIndex',
                             f'{ip} - - [] "GET / HTTP/1.1" 403 10 "-" "normal"',
                             f'{ip} - - [] "GET /index.php HTTP/1.1" 200 10 "http://evil/.env" "[client 203.0.113.8] AH01276"']:
                    r.search([(line,'','')]);self.assertFalse(r.hasMatched())

    def test_autoindex_semantic_veto_and_legitimate_error_fixtures(self):
        stamp = __import__('time').strftime('%a %b %d %H:%M:%S %Y')
        for peer in ['198.51.100.77', '2001:db8::77']:
            def line(directory):
                return f'[{stamp}] [autoindex:error] [pid 123:tid 123] [client {peer}:54321] AH01276: Cannot serve directory {directory}: No matching DirectoryIndex (index.html,index.php) found, and server-generated directory index forbidden by Options directive'
            for directory in ['/var/www/html/', '/var/www/html/whmcs/', '/var/www/html/public/', '/var/www/html/.env.example/']:
                self.assertTrue(H['non_offensive_line'](line(directory)))
                self.assertTrue(H['non_offensive_line'](line(directory)+', referer: https://example.invalid/.env'))
            for directory in ['/var/www/html/.git/', '/var/www/html/.env/', '/var/www/html/.aws/credentials/', '/var/www/html/wp-admin/', '/var/www/html/.env.example/.git/', '/var/www/html/.git/.env.example/']:
                self.assertFalse(H['non_offensive_line'](line(directory)))
            regex = r'^\[\s*\]\s+\[autoindex:error\]\s+\[pid \d+:tid \d+\]\s+\[client <HOST>:\d+\] AH01276: Cannot serve directory /var/www/html/:.*'
            with self.assertRaisesRegex(ValueError, 'legitimate|signals|offensive'):
                H['validate_filter']('[Definition]\nfailregex = '+regex+'\nignoreregex =\n',[line('/var/www/html/')])
            sensitive = regex.replace('/var/www/html/', r'/var/www/html/\.git/')
            H['validate_filter']('[Definition]\nfailregex = '+sensitive+'\nignoreregex =\n',[line('/var/www/html/.git/')])
        self.assertTrue(any('AH01276:' in entry for entry in H['legitimate_lines']()))

    def test_sensitive_signatures_remain_independent_ipv4_ipv6(self):
        regex=H['parse'](H['sensitive_filter'](list(H['PROBE_GROUPS']))).get('Definition','failregex').replace('%%','%')
        for ip in ['198.51.100.77','2001:db8::77']:
            for path in ['/.env','/.git/config','/wp-config.php','/icons/.%2e/%2e%2e/x',
                         '/retired-page?lang=/../../../..//////////dev/cmdb/sslvpn_websession']:
                r=FailRegex(regex);line=f'{ip} - - [] "GET {path} HTTP/1.1" 403 10 "-" "normal"'
                r.search([(line,'','')]);self.assertTrue(r.hasMatched());self.assertEqual(r.getHost(),ip)
            for path in ['/','/retired-page','/clientarea.php']:
                r=FailRegex(regex);r.search([(f'{ip} - - [] "GET {path} HTTP/1.1" 403 10 "-" "normal"','','')]);self.assertFalse(r.hasMatched())

if __name__=='__main__':unittest.main()
