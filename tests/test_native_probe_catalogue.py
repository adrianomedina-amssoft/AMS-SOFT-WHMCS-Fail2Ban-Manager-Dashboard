import runpy
import time
import unittest
from pathlib import Path
from fail2ban.server.failregex import FailRegex

ROOT = Path(__file__).resolve().parents[1]
H = runpy.run_path(str(ROOT/'setup/amsfb-admin'))


class NativeProbeCatalogue(unittest.TestCase):
    def test_audited_webshell_targets_are_closed_and_independent(self):
        r = self.expression(['webshell_probe'])
        targets = ['/wp-filemanager1.php', '/wp-security.php?p=',
                   '/wp-content/plugins/hellopress/wp_filemanager.php']
        for target in targets:
            for ip in ('198.51.100.77', '2001:db8::77'):
                for status in (200, 301, 302, 403, 404, 421, 500):
                    self.assertEqual(self.hit(r, target, ip=ip, status=status), ip)
        for target in ['/1.php', '/random.php', '/index.php', '/wp-security.php.txt',
                       '/wp-filemanager1.php/extra', '/prefix/wp-security.php',
                       '//wp-security.php', '/wp-filemanager.php',
                       '/wp-content/plugins/hellopress/other.php',
                       '/index.php?path=/wp-security.php']:
            self.assertIsNone(self.hit(r, target, tail='"/wp-security.php" "GET /wp-filemanager1.php HTTP/1.1"'))
        self.assertIsNone(self.hit(self.expression(['env']), '/wp-security.php'))
        disabled = FailRegex(H['parse'](H['sensitive_filter'](['webshell_probe'], False)).get('Definition','failregex'))
        self.assertIsNone(self.hit(disabled, '/wp-security.php'))

    def expression(self, groups=None):
        text = H['sensitive_filter'](groups or list(H['PROBE_GROUPS']))
        return FailRegex(H['parse'](text).get('Definition', 'failregex').replace('%%', '%'))

    def hit(self, expression, target, ip='198.51.100.77', status=301, method='GET', tail='"-" "normal"'):
        expression.search([(f'{ip} - - [] "{method} {target} HTTP/1.1" {status} 100 {tail}', '', '')])
        return expression.getHost() if expression.hasMatched() else None

    def test_closed_repository_and_credentials_targets(self):
        targets = ['/.git', '/.git/', '/.git/config', '/.git/HEAD', '/.git/info/refs', '/.git/logs/HEAD',
                   '/.git/description', '/.svn', '/.svn/', '/.svn/wc.db', '/.svn/entries',
                   '/.aws/credentials', '/.aws/config.bak', '/.docker/config.json', '/.ssh/authorized_keys',
                   '/.ssh/known_hosts', '/.ssh/id_rsa.old', '/.kube/config', '/.git-credentials', '/.netrc',
                   '/.pypirc', '/.boto', '/.npmrc', '/configuration.php.bak', '/config.php.old',
                   '/wp-config.php~', '/wp-config.php.orig', '/wp-config.php.save']
        r = self.expression()
        for target in targets:
            for ip in ('198.51.100.77', '2001:db8::77'):
                with self.subTest(target=target, ip=ip):self.assertEqual(self.hit(r, target, ip), ip)

    def test_claude_credential_target_and_similar_names(self):
        # Independent credentials group, bounded secret filename and real peer.
        r = self.expression(['credentials'])
        for target in ['/.claude/.credentials.json', '/home/.claude/.credentials.json',
                       '/.CLAUDE/.CREDENTIALS.JSON', '/%2eclaude/%2ecredentials%2ejson',
                       '/%252eclaude%252f%252ecredentials%252ejson', '/.claude/.credentials.json.bak']:
            for ip in ('198.51.100.77', '2001:db8::77'):
                for status in (200, 301, 403, 404, 421):
                    with self.subTest(target=target, ip=ip, status=status):
                        self.assertEqual(self.hit(r, target, ip=ip, status=status), ip)
        for target in ['/.claude/settings.json', '/.claude/settings.local.json',
                       '/.claude/credentials.json', '/.claude/.credentials.json.txt',
                       '/.claude/.credentials.json-example', '/.claude/', '/credentials.json',
                       '/index.php?file=/.claude/.credentials.json']:
            self.assertIsNone(self.hit(r, target))
        self.assertIsNone(self.hit(self.expression(['env']), '/.claude/.credentials.json'))

    def test_audited_gpon_post_target_only(self):
        r = self.expression(['gpon_probe'])
        for target in ['/GponForm/diag_Form?style/', '/gponform/DIAG_FORM?STYLE/']:
            for ip in ('198.51.100.77', '2001:db8::77'):
                for status in (200, 301, 403, 404, 421, 500):
                    with self.subTest(target=target, ip=ip, status=status):
                        self.assertEqual(self.hit(r, target, ip=ip, status=status, method='POST'), ip)
        for method in ('GET', 'HEAD', 'OPTIONS', 'XPOST'):
            self.assertIsNone(self.hit(r, '/GponForm/diag_Form?style/', method=method))
        for target in ['/GponForm', '/GponForm/diag_Form', '/GponForm/diag_Form?images/',
                       '/GponForm/diag_Form?style', '/GponForm/diag_Form?style/&x=1',
                       '/GponForm/diag_Form/extra?style/', '/api/GponForm/diag_Form?style/',
                       '//GponForm/diag_Form?style/', '/GponForm/diag_Form?x=style/',
                       '/index.php?url=/GponForm/diag_Form?style/', '/GponForm/diag_Form?style/x']:
            self.assertIsNone(self.hit(r, target, method='POST'))
        self.assertIsNone(self.hit(r, '/', method='POST',
                                  tail='"/GponForm/diag_Form?style/" "POST /GponForm/diag_Form?style/ HTTP/1.1"'))
        self.assertIsNone(self.hit(self.expression(['env']), '/GponForm/diag_Form?style/', method='POST'))
        self.assertEqual(self.hit(self.expression(), '/GponForm/diag_Form?style/', method='POST'), '198.51.100.77')
        disabled = FailRegex(H['parse'](H['sensitive_filter'](['gpon_probe'], False)).get('Definition', 'failregex'))
        self.assertIsNone(self.hit(disabled, '/GponForm/diag_Form?style/', method='POST'))

    def test_documented_phpunit_endpoints(self):
        r = self.expression(['phpunit'])
        for target in ['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
                       '/lib/phpunit/Util/PHP/eval-stdin.php', '/phpunit/src/Util/PHP/eval-stdin.php',
                       '//api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
                       '/api/vendor/phpunit/phpunit/src/Util/PHP/Template/eval-stdin.php',
                       '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php.dev']:
            for method in ('GET', 'POST', 'HEAD'):
                with self.subTest(target=target, method=method):self.assertEqual(self.hit(r, target, method=method), '198.51.100.77')

    def test_specific_debug_targets_only(self):
        r = self.expression(['debug'])
        for target in ['/phpinfo', '/phpinfo.php', '/info.php', '/_profiler/phpinfo',
                       '/storage/logs/laravel.log', '/_ignition/execute-solution']:
            self.assertEqual(self.hit(r, target), '198.51.100.77')
        for target in ['/info', '/debug', '/_profiler', '/storage/files/laravel.log', '/config.json', '/test.php']:
            self.assertIsNone(self.hit(r, target))

    def test_db_admin_versions_and_site_scope(self):
        # The production preflight separately verifies there is no phpMyAdmin alias.
        r = self.expression(['db_admin'])
        for target in ['/phpMyAdmin/', '/phpmyadmin/index.php?lang=en', '/phpMyAdmin3/index.php',
                       '/phpMyAdmin-5.2.1-english/index.php', '/sql/phpMyAdmin/index.php',
                       '/administrator/PMA/index.php', '/php-myadmin/', '/MyAdmin/index.php']:
            self.assertEqual(self.hit(r, target), '198.51.100.77')
        for target in ['/admin', '/administrator', '/mysql', '/database', '/phpmyadministrator', '/pmanager']:
            self.assertIsNone(self.hit(r, target))

    def test_encoding_case_and_documented_env_space_variants(self):
        r = self.expression()
        for target in ['/%252eenv', '/%252egit%252fconfig', '/.ENV', '/.GIT/CONFIG', '/docker/.env%20',
                       '/.env.production%20', '/.env.project%20%20', '/%2eaws%2fcredentials']:
            self.assertEqual(self.hit(r, target), '198.51.100.77')
        for target in ['/.env.example%20', '/.ENV.SAMPLE', '/.env.dist%20', '/docs/.env.example/readme']:
            self.assertIsNone(self.hit(r, target))

    def test_normal_targets_similar_names_queries_and_trailing_forgery(self):
        r = self.expression()
        negatives = ['/', '/clientarea.php', '/checkout.php', '/api', '/login', '/admin', '/wp-json',
                     '/retired-page', '/config.php', '/configuration.php', '/config.json', '/backup.zip',
                     '/.git/configuration', '/.gitignore', '/.netrc.txt', '/configuration.php.backup-not-known',
                     '/phpinfo.html', '/myadministrator', '/docs/phpunit/eval-stdin.php',
                     '/index.php?file=/.env', '/docs?url=/.git/config', '/clientarea.php?action=invoices']
        for target in negatives:
            self.assertIsNone(self.hit(r, target, tail='"https://example.com/.env" "GET /phpmyadmin/index.php HTTP/1.1"'))
        self.assertEqual(self.hit(r, '/.git/config?ip=203.0.113.44', ip='2001:db8::77',
                                  tail='"203.0.113.44" "[client 203.0.113.55]"'), '2001:db8::77')

    def test_status_does_not_prevent_closed_signature_detection(self):
        r = self.expression()
        for status in (200, 301, 302, 403, 404, 421, 500):
            for target in ('/.env', '/.git/config', '/phpmyadmin/index.php', '/_ignition/execute-solution'):
                self.assertEqual(self.hit(r, target, status=status), '198.51.100.77')

    def test_new_groups_are_independently_configurable(self):
        for group, target in [('phpunit', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'),
                              ('debug', '/phpinfo.php'), ('db_admin', '/phpmyadmin/index.php')]:
            self.assertEqual(self.hit(self.expression([group]), target), '198.51.100.77')
            self.assertIsNone(self.hit(self.expression(['env']), target))

    def test_exchange_exact_targets_and_independent_group(self):
        r = self.expression(['exchange_probe'])
        targets = ['/owa/auth/x.js', '/owa/auth/x.js?x=1', '/OWA/AUTH/X.JS',
                   '/autodiscover/autodiscover.json?@zdi/Powershell',
                   '/autodiscover/autodiscover.json?@ZDI/powershell',
                   '/owa%2fauth%2fx%2ejs', '/owa%252fauth%252fx%252ejs']
        for target in targets:
            for ip in ('198.51.100.77', '2001:db8::77'):
                for status in (200, 301, 403, 404, 421):
                    self.assertEqual(self.hit(r, target, ip=ip, status=status), ip)
            self.assertIsNone(self.hit(self.expression(['env']), target))
        for target in ['/owa', '/owa/', '/owa/auth/other.js', '/owa/auth/x.jsx',
                       '/owa/auth/x.js/extra', '/prefix/owa/auth/x.js', '/docs/owa/auth/x.js',
                       '/autodiscover/autodiscover.json', '/autodiscover/autodiscover.json?x=1',
                       '/autodiscover/autodiscover.json?@zdi/Powershell-other',
                       '/autodiscover/autodiscover.json?@zdi/Powershell/extra',
                       '/autodiscover/autodiscover.json?@zdi/Powershell&x=1',
                       '/ecp/', '/index.php?next=/owa/auth/x.js', '/retired-page']:
            self.assertIsNone(self.hit(r, target, tail='"/owa/auth/x.js" "GET /autodiscover/autodiscover.json?@zdi/Powershell HTTP/1.1"'))
        self.assertEqual(self.hit(r, '/owa/auth/x.js', ip='2001:db8::77', tail='"203.0.113.44" "[client 203.0.113.55]"'), '2001:db8::77')

    def test_boundary_and_long_malformed_request_are_bounded(self):
        r = self.expression();start = time.monotonic()
        self.assertIsNone(self.hit(r, '/phpmyadmin'*800, status=999))
        self.assertLess(time.monotonic()-start, 0.5)
        for target in ['/phpmyadmin-malicious-not-version', '/.git/configuration']:
            self.assertIsNone(self.hit(r, target))


if __name__ == '__main__':
    unittest.main()
