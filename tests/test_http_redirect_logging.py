import importlib.util
from pathlib import Path
import runpy
import unittest
from fail2ban.server.failregex import FailRegex
from fail2ban.server.datedetector import DateDetector

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('http_redirect_audit', ROOT/'scripts/http_redirect_audit.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
H = runpy.run_path(str(ROOT/'setup/amsfb-admin'))


class HttpRedirectLogging(unittest.TestCase):
    def config(self, directive='', extra='', port='*:80'):
        return '<VirtualHost '+port+'>\nServerName whmcs.example.invalid\nServerAlias www.whmcs.example.invalid\n'+directive+'\n'+extra+'\nRedirect permanent / https://whmcs.example.invalid/\n</VirtualHost>'

    def row(self, text):
        return AUDIT.inspect_text(text)[0]

    def test_original_gap_is_reproduced(self):
        self.assertEqual(self.row(self.config())['reason'], 'explicit_http_log_missing')

    def test_both_approved_named_sources_and_default(self):
        for path in AUDIT.APPROVED_LOGS:
            row = self.row(self.config('CustomLog '+path+' combined'))
            self.assertEqual(row['status'], 'configured')
            self.assertEqual(AUDIT.check_coverage([row], list(AUDIT.APPROVED_LOGS))[0]['status'], 'covered')

    def test_variables_aliases_quoted_paths_and_comments(self):
        row = self.row('# <VirtualHost *:80> fake\n'+self.config('CustomLog "${APACHE_LOG_DIR}/access_whmcs.log" combined # keep peer'))
        self.assertEqual(row['log'], '/var/log/apache2/access_whmcs.log')
        self.assertEqual(row['aliases'], ['www.whmcs.example.invalid'])

    def test_unmonitored_paths_and_formats_fail_closed(self):
        for directive, reason in [
            ('CustomLog /var/log/apache2/other_vhosts_access.log vhost_combined', 'log_not_approved'),
            ('CustomLog /var/log/apache2/access_whmcs.log vhost_combined', 'format_not_combined'),
            ('CustomLog /tmp/capture.log combined', 'log_not_approved'),
            ('CustomLog /var/log/apache2/access_whmcs.log combined env=trace', 'conditional_or_unsupported_customlog'),
            ('CustomLog "|/usr/bin/tee /tmp/x" combined', 'log_not_approved'),
        ]:
            with self.subTest(directive=directive):
                self.assertEqual(self.row(self.config(directive))['reason'], reason)
        row = self.row(self.config('CustomLog /var/log/apache2/access_whmcs.log combined'))
        self.assertEqual(AUDIT.check_coverage([row], ['/var/log/apache2/access.log'])[0]['reason'], 'loaded_jail_source_missing')

    def test_indirect_conditional_duplicate_and_malformed_are_unknown(self):
        good = 'CustomLog /var/log/apache2/access_whmcs.log combined'
        for extra in ['Include /etc/apache2/http.inc', 'IncludeOptional other.conf', '<IfModule mod_log_config.c>\n'+good+'\n</IfModule>',
                      'GlobalLog /tmp/x combined', 'LogFormat "x" combined', good, 'ServerName other.example']:
            with self.subTest(extra=extra):
                self.assertEqual(self.row(self.config(good, extra))['status'], 'unknown')
        self.assertEqual(self.row('<VirtualHost *:80>')['reason'], 'unbalanced_virtualhost')
        self.assertEqual(self.row(self.config('CustomLog "unterminated'))['reason'], 'directive_syntax')

    def test_https_is_not_misreported_as_an_http_gap(self):
        self.assertEqual(AUDIT.inspect_text(self.config(port='*:443')), [])
        self.assertEqual(len(AUDIT.inspect_text(self.config()+self.config(port='*:443'))), 1)
        self.assertEqual(self.row(self.config(port='[::]:80'))['addresses'], ['[::]:80'])

    def test_sensitive_301_targets_match_native_peer_not_trailing_fields(self):
        text = H['sensitive_filter'](list(H['PROBE_GROUPS']))
        regex = H['parse'](text).get('Definition', 'failregex').replace('%%', '%')
        for ip in ['198.51.100.77', '2001:db8::77']:
            for target in ['/.env', '/.git/config', '/wp-config.php', '/%2eenv', '/wp-login.php']:
                line = ip+' - - [16/Oct/2026:11:32:09 -0300] "GET '+target+' HTTP/1.1" 301 496 "203.0.113.44" "[client 203.0.113.55]"'
                d = DateDetector();d.addDefaultTemplate();m = d.matchTime(line)[0]
                r = FailRegex(regex);r.search([(line[:m.start(1)], line[m.start(1):m.end(1)], line[m.end(1):])])
                self.assertTrue(r.hasMatched());self.assertEqual(r.getHost(), ip)

    def test_normal_or_retired_routes_do_not_become_one_hit_targets(self):
        regex = H['parse'](H['sensitive_filter'](list(H['PROBE_GROUPS']))).get('Definition', 'failregex').replace('%%', '%')
        for target in ['/', '/robots.txt', '/retired-page', '/clientarea.php', '/.env.example', '/.git/configuration', '/index.php?file=/.env']:
            r = FailRegex(regex);r.search([('198.51.100.77 - - [] "GET '+target+' HTTP/1.1" 301 10 "-" "scanner"', '', '')])
            self.assertFalse(r.hasMatched())


if __name__ == '__main__':
    unittest.main()
