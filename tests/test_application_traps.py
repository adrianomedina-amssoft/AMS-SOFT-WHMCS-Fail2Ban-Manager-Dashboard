import json,runpy,subprocess,time,unittest
from pathlib import Path
from fail2ban.server.failregex import FailRegex

ROOT=Path(__file__).resolve().parents[1]
H=runpy.run_path(str(ROOT/'setup/amsfb-admin'))
NEW=list(H['APPLICATION_TRAPS'])
def expression(groups=None,enabled=True):
    text=H['sensitive_filter'](NEW if groups is None else groups,enabled)
    return FailRegex(H['parse'](text).get('Definition','failregex').replace('%%','%'))
def record(target,status=404,ip='198.51.100.77',method='GET',tail='"-" "fixture"'):
    return f'{ip} - - [] "{method} {target} HTTP/1.1" {status} 10 {tail}'
def hit(regex,line):
    regex.search([(line,'','')])
    return regex.getHost() if regex.hasMatched() else None

class ApplicationTrapTests(unittest.TestCase):
    def test_php_python_catalog_and_conservative_defaults(self):
        r=subprocess.run(['php',str(ROOT/'tests/application_traps.php'),'--json'],capture_output=True,text=True,check=True)
        catalog=json.loads(r.stdout)
        self.assertEqual(catalog['groups'],list(H['PROBE_GROUPS']))
        self.assertEqual(catalog['application_traps'],{k:list(v) for k,v in H['APPLICATION_TRAPS'].items()})
        self.assertFalse(set(NEW)&set(catalog['default_groups']))
        self.assertEqual(len(catalog['default_groups']),16)

    def test_exact_targets_all_status_methods_queries_and_peers(self):
        regex=expression()
        for paths in H['APPLICATION_TRAPS'].values():
            for target in paths:
                for query in ('','?a=1','?next=%2Fclientarea.php'):
                    for ip in ('198.51.100.77','2001:db8::77'):
                        for status in (200,301,302,403,404,421,500):
                            for method in ('GET','HEAD','POST','OPTIONS'):
                                with self.subTest(target=target,query=query,ip=ip,status=status,method=method):
                                    self.assertEqual(hit(regex,record(target+query,status,ip,method)),ip)

    def test_independent_selection_and_disable(self):
        for selected in NEW:
            for group,paths in H['APPLICATION_TRAPS'].items():
                for target in paths:
                    self.assertEqual(hit(expression([selected]),record(target)),'198.51.100.77' if group==selected else None)
                    self.assertIsNone(hit(expression([selected],False),record(target)))
        old=[g for g in H['PROBE_GROUPS'] if g not in NEW]
        for paths in H['APPLICATION_TRAPS'].values():
            for target in paths:self.assertIsNone(hit(expression(old),record(target)))
        self.assertEqual(hit(expression(list(H['PROBE_GROUPS'])),record('/.env')),'198.51.100.77')

    def test_no_prefix_suffix_case_decoding_or_normal_routes(self):
        regex=expression()
        paths=['/','/web/login','/api/v1/version','/actuator/health','/actuator/env','/admin','/api','/login','/graylog',
               '/developmentserver/metadatauploader.txt','/druid/indexXhtml','/web/database/listing','/xmlrpc/2/commonality',
               '/remote/login','/cgi-bin/login.cgi','/sonicui/7/sslvpn-portal','/+CSCOE+/logonXhtml',
               '/api/sonicos/authentication','/api/sonicos/tfa/','/vpn/pluginlist.xml.bak']
        for values in H['APPLICATION_TRAPS'].values():
            for target in values:
                paths.extend(['/prefix'+target,target+'/',target+'/child',target+'.bak',target.upper(),'/'+target,
                              target.replace('/', '%2f',1),target+'#fragment'])
        for path in paths:
            with self.subTest(path=path):self.assertIsNone(hit(regex,record(path)))

    def test_untrusted_fields_cannot_select_target_or_peer(self):
        regex=expression()
        for values in H['APPLICATION_TRAPS'].values():
            for target in values:
                self.assertIsNone(hit(regex,record('/clientarea.php',tail=f'"{target}" "GET {target} HTTP/1.1"')))
                self.assertIsNone(hit(regex,record('/index.php?next='+target)))
                self.assertEqual(hit(regex,record(target+'?ip=203.0.113.99',tail='"203.0.113.98" "[client 203.0.113.97]"')),'198.51.100.77')
                error='[] [authz_core:error] [pid 123] [client 198.51.100.77:12345] AH01630: client denied by server configuration: /var/www/html'+target
                self.assertIsNone(hit(regex,error))

    def test_malformed_and_bounded_envelope(self):
        regex=expression();started=time.monotonic()
        for line in (record('/druid/index.html',999),record('/druid/index.html').replace('HTTP/1.1','HTTP/1.12345'),
                     record('/druid/index.html?x='+'a'*8192),record('/prefix/'*1000+'druid/index.html'),
                     record('/druid/index.html').replace('"GET ', '"get ')):
            self.assertIsNone(hit(regex,line))
        self.assertLess(time.monotonic()-started,0.5)

if __name__=='__main__':unittest.main()
