import runpy
import unittest
import time
from pathlib import Path
from fail2ban.server.failregex import FailRegex
from fail2ban.server.datedetector import DateDetector

H=runpy.run_path(str(Path(__file__).resolve().parents[1]/'setup/amsfb-admin'))

class SensitiveProbes(unittest.TestCase):
    def expression(self,groups=None,enabled=True):
        text=H['sensitive_filter'](groups or list(H['PROBE_GROUPS']),enabled)
        return FailRegex(H['parse'](text).get('Definition','failregex').replace('%%','%'))
    def hit(self,path,status=404,ip='198.51.100.77',method='GET',tail='"-" "normal"',groups=None,enabled=True):
        line=ip+' - - [15/Oct/2026:02:30:00 -0300] "'+method+' '+path+' HTTP/1.1" '+str(status)+' 100 '+tail
        d=DateDetector();d.addDefaultTemplate();m=d.matchTime(line)[0]
        r=self.expression(groups,enabled);r.search([(line[:m.start(1)],line[m.start(1):m.end(1)],line[m.end(1):])])
        return r.getHost() if r.hasMatched() else None
    def test_sensitive_targets_and_encoding(self):
        paths=['/.env','/.env.secret','/.env.dev.local','/account/.env','//.env','/.//.env',
            '/..%2f.env','/static//home/user/.env','/api/..;/.env','/%2eenv','/%2Egit%2Fconfig',
            '/.git/config','/.git/HEAD','/.git/index','/.svn/wc.db','/.svn/entries',
            '/wp-config.php','/blog/wp-config.php.bak','/.aws/credentials','/.docker/config.json',
            '/.ssh/id_rsa','/.npmrc','/xmlrpc.php','/blog/xmlrpc.php','/wp-login.php','/wp-admin/',
            '/administrator/manifests/files/joomla.xml','/magento_version','/core/install.php']
        for path in paths:
            with self.subTest(path=path):self.assertEqual(self.hit(path),'198.51.100.77')
    def test_status_is_not_authority_and_peer_is_exact(self):
        for status in [200,301,403,404,421,500]:
            self.assertEqual(self.hit('/.env',status=status,ip='2001:db8::77'),'2001:db8::77')
            self.assertIsNone(self.hit('/retired-page',status=status))
        self.assertEqual(self.hit('/.git/config?ip=203.0.113.44',tail='"203.0.113.44" "[client 203.0.113.55]"'),'198.51.100.77')
        self.assertEqual(self.hit('/.env',method='POST'),'198.51.100.77')
    def test_normal_queries_and_similar_names(self):
        for path in ['/','/clientarea.php','/checkout.php','/admin','/retired-page',
                     '/docs/.env.example','/.env.sample','/.env.dist','/%2eenv%2eexample%2freadme',
                     '/.environment','/.git/configuration','/wp-config.php.txt',
                     '/index.php?file=/.env','/docs?url=/.git/config','/env']:
            with self.subTest(path=path):self.assertIsNone(self.hit(path))
        self.assertIsNone(self.hit('/index.php',tail='"https://example.com/.env" "GET /.git/config HTTP/1.1"'))
    def test_catalog_and_detection_disable(self):
        self.assertIsNone(self.hit('/.git/config',groups=['env']))
        self.assertIsNone(self.hit('/.env',enabled=False))
        for groups in [[],['env','.*'],['/etc/passwd'],'env']:
            with self.assertRaises(ValueError):H['sensitive_filter'](groups)
    def test_traversal_and_fingerprint(self):
        for path in ['/icons/.%2e/%2e%2e/apache2/icons/x','/icons/.%%32%65/.%%32%65/apache2/icons/x','/a/%252e%252e/x','/wp-includes/wlwmanifest.xml']:
            self.assertEqual(self.hit(path),'198.51.100.77')
        self.assertIsNone(self.hit('/icons/.%2e/%2e%2e/x',groups=['env']))
    def test_traversal_error_header_peer_and_negative(self):
        text=H['traversal_filter']();r=FailRegex(H['parse'](text).get('Definition','failregex').replace('%%','%'))
        for ip in ['198.51.100.77','2001:db8::77']:
            line='[] [core:error] [pid 123:tid 45] [client '+ip+':54321] AH10244: invalid URI path (/icons/.%%32%65/.%%32%65/apache2/icons/x)'
            r.search([(line,'','')]);self.assertTrue(r.hasMatched());self.assertEqual(r.getHost(),ip)
        for line in ['[] [core:error] [pid 123] [client 198.51.100.77:123] AH10244: invalid URI path (/normal)',
                     '[] [ssl:error] [pid 123] [client 198.51.100.77:123] AH02032: Hostname mismatch']:
            r.search([(line,'','')]);self.assertFalse(r.hasMatched())
    def test_semantic_veto_including_mixed_regex(self):
        benign='198.51.100.77 - - [15/Oct/2026:10:30:00 -0300] "GET /retired-page HTTP/1.1" 421 100 "-" "scanner"'
        attack=benign.replace('/retired-page','/.env').replace('421','404')
        self.assertTrue(H['non_offensive_line'](benign));self.assertFalse(H['non_offensive_line'](attack))
        self.assertTrue(H['non_offensive_line'](benign.replace('/retired-page','/retired-page?file=/.env')))
        self.assertTrue(H['non_offensive_line'](benign.replace('/retired-page','/retired-page?file=/.aws/credentials')))
        for pattern in [r'^<HOST> - \S+ \[\s*\] "GET /retired-page HTTP/1\.1" 421 \S+',
                        r'^<HOST> - \S+ \[\s*\] "GET /(?:retired-page|\.env) HTTP/1\.1" (?:421|404) \S+']:
            with self.assertRaisesRegex(ValueError,'signals|offensive'):H['validate_filter']('[Definition]\nfailregex = '+pattern+'\nignoreregex =\n',[benign,attack])
        denied='[Thu Oct 15 10:30:00 2026] [authz_core:error] [pid 123] [client 198.51.100.77:123] AH01630: client denied by server configuration: /var/www/html/license/, referer: http://example.com/.env'
        self.assertTrue(H['non_offensive_line'](denied))
        self.assertFalse(H['non_offensive_line'](denied.replace('license/,','license/.env,')))
    def test_full_native_validator(self):
        text=H['sensitive_filter'](list(H['PROBE_GROUPS']))
        line='198.51.100.77 - - [15/Oct/2026:02:30:00 -0300] "GET /.env HTTP/1.1" 404 100 "-" "normal"'
        H['validate_filter'](text,[line])
    def test_query_traversal_overrides_normal_route_veto(self):
        for payload in ['/../../../..//////////dev/cmdb/sslvpn_websession','/%2e%2e/%2e%2e/x','/%252e%252e%252fetc/passwd','/etc/passwd']:
            for ip in ['198.51.100.77','2001:db8::77']:
                line=ip+' - - [15/Oct/2026:11:30:00 -0300] "GET /retired-page?lang='+payload+' HTTP/1.1" 200 10 "-" "fixture"'
                self.assertFalse(H['non_offensive_line'](line))
        for payload in ['pt-br','/.env','/.git/config','/.aws/credentials','https://example.com/docs']:
            line='198.51.100.77 - - [15/Oct/2026:11:30:00 -0300] "GET /retired-page?lang='+payload+' HTTP/1.1" 421 10 "-" "fixture"'
            self.assertTrue(H['non_offensive_line'](line))
        forged='198.51.100.77 - - [15/Oct/2026:11:30:00 -0300] "GET /clientarea.php HTTP/1.1" 200 10 "https://example.com/?lang=/../../etc/passwd" "GET /?x=/etc/passwd HTTP/1.1"'
        self.assertTrue(H['non_offensive_line'](forged))
        # The veto correction does not broaden the native one-hit catalogue.
        self.assertIsNone(self.hit('/retired-page?lang=/../../etc/passwd',status=200,groups=['traversal']))
    def test_native_query_traversal_closed_catalogue(self):
        for value in ['/../../../..//////////dev/cmdb/sslvpn_websession','../../etc/passwd','/%2e%2e/%2e%2e/etc/passwd','/%252e%252e%252f%252e%252e%252fetc%252fshadow','../../proc/self/environ','../../windows/win.ini']:
            for ip in ['198.51.100.77','2001:db8::77']:
                self.assertEqual(self.hit('/retired-page?x=1&lang='+value+'&a=2',ip=ip,groups=['query_traversal']),ip)
        for value in ['../etc/passwd','/etc/passwd','../../docs/manual.pdf','../../etc/passwd.example','../../etc/passwd/child','https://example.com/../../etc/passwd','/.env','/.git/config','pt-br']:
            self.assertIsNone(self.hit('/retired-page?lang='+value,groups=['query_traversal']))
        for target in ['/index.php?note=../../etc/passwd','/index.php?lang=../../docs/manual.pdf','/docs/../../etc/passwd?lang=pt-br']:
            self.assertIsNone(self.hit(target,groups=['query_traversal']))
        self.assertIsNone(self.hit('/index.php',groups=['query_traversal'],tail='"https://example.com/?lang=../../etc/passwd" "GET /?file=../../etc/passwd HTTP/1.1"'))
        started=time.monotonic();self.assertIsNone(self.hit('/index.php?'+'a=&'*1000+'lang=../../docs/manual.pdf',groups=['query_traversal']));self.assertLess(time.monotonic()-started,0.5)
    def test_individually_proved_query_rule_can_validate(self):
        line='198.51.100.77 - - [15/Oct/2026:11:30:00 -0300] "GET /retired-page?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1" 200 10 "-" "fixture"'
        text='[Definition]\nfailregex = ^<HOST> - \\S+ \\[\\s*\\] "GET /retired-page\\?lang=/\\.\\./\\.\\./\\.\\./\\.\\.[^ "]* HTTP/[^\"]+" 200 \\d+\nignoreregex =\n'
        result=H['validate_filter'](text,[line]);self.assertEqual(len(result['matched_sha256']),1)
    def test_long_malformed_envelope_fails_before_path_backtracking(self):
        r=self.expression();path='/wp-admin'*900
        for ending in [' HTTP/1.1" 999 100 "-" "-"',' HTTP/1.12345" 400 100 "-" "-"']:
            line='198.51.100.77 - - [] "GET '+path+ending;t=time.monotonic()
            r.search([(line,'','')]);self.assertFalse(r.hasMatched())
            self.assertLess(time.monotonic()-t,0.5)
    def test_payload_cannot_choose_files_actions_or_unbounded_values(self):
        p=dict(enabled=1,groups=['env'],maxretry=1,findtime=60,bantime=300,whitelist=[])
        for key,value in [('action','iptables-allports'),('maxretry',0),('enabled',True),('bantime',-1)]:
            with self.assertRaises(ValueError):H['sync_sensitive_probes'](dict(p,**{key:value}))

if __name__=='__main__':unittest.main()
