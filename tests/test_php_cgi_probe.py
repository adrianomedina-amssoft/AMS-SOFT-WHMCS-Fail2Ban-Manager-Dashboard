import json,re,runpy,subprocess,time,unittest
from pathlib import Path
from unittest.mock import patch
from fail2ban.server.failregex import FailRegex

ROOT=Path(__file__).resolve().parents[1]
H=runpy.run_path(str(ROOT/'setup/amsfb-admin'))
GLOBALS=H['non_offensive_line'].__globals__
PAYLOAD='/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input'

def line(target,status=421,ip='198.51.100.77',method='POST',tail='"-" "fixture"'):
    return f'{ip} - - [] "{method} {target} HTTP/1.1" {status} 10 {tail}'

def php(lines):
    r=subprocess.run(['php',str(ROOT/'tests/php_cgi_probe.php'),'--json'],
                     input=json.dumps({'lines':lines}),text=True,capture_output=True,timeout=20)
    if r.returncode:raise RuntimeError(r.stderr)
    return json.loads(r.stdout)

class PhpCgiProbeTests(unittest.TestCase):
    @staticmethod
    def expression(groups=None,enabled=True):
        text=H['sensitive_filter'](groups or ['php_cgi_probe'],enabled)
        return FailRegex(H['parse'](text).get('Definition','failregex').replace('%%','%'))
    @staticmethod
    def hit(expr,record):
        expr.search([(record,'','')])
        return expr.getHost() if expr.hasMatched() else None

    def test_cross_language_positive_negative_status_peer_and_selection(self):
        variants=[PAYLOAD,PAYLOAD.replace('%ADd','-d'),PAYLOAD.replace('%ADd','%2Dd'),
            PAYLOAD.replace('%ADd','%252Dd'),PAYLOAD.replace('%ADd','%25ADd'),
            PAYLOAD.replace('%ADd','%C2%ADd'),PAYLOAD.replace('%ADd','%25C2%25ADd'),
            PAYLOAD.replace('+','%20'),PAYLOAD.replace('+','%2520'),
            PAYLOAD.replace('%3d','%253D').replace('php://input','php%253A%252F%252Finput'),
            PAYLOAD.replace('1+','on+'),PAYLOAD.replace('1+','true+'),
            '/index.php?-d+auto_prepend_file=php://input+-d+allow_url_include=on',
            PAYLOAD.replace('%ADd','\u00add')]
        cases=[]
        for target in variants:
            for status in (200,301,302,403,404,421,500):
                for ip in ('198.51.100.77','2001:db8::77'):
                    for method in ('GET','POST','HEAD'):
                        cases.append((line(target,status,ip,method),ip,True))
        negatives=['/','/index.php','/clientarea.php','/login','/checkout.php',
            '/?allow_url_include=1&auto_prepend_file=php://input',
            PAYLOAD.replace('1+','0+'),PAYLOAD.replace('1+','off+'),
            PAYLOAD.replace('php://input','php://input.txt'),
            PAYLOAD.replace('php://input','/tmp/example.php'),
            '/?notes='+PAYLOAD[2:], '/?allow_url_include=1',
            PAYLOAD.replace('%ADd','d'),PAYLOAD.replace('%ADd','%2525ADd'),
            '/?%ADd+auto_prepend_file=php://input','/index.php?doc=auto_prepend_file',
            PAYLOAD+'&other=1','/'+('a'*8192)+PAYLOAD]
        cases += [(line(target,tail=f'"{PAYLOAD}" "{PAYLOAD}"'),None,False) for target in negatives]
        cases += [('[Tue Oct 20 10:51:52.0 2026] [ssl:error] [pid 123] [client 198.51.100.77:12] AH02032: Hostname mismatch '+PAYLOAD,None,False)]
        result=php([x[0] for x in cases]);self.assertEqual(result['pattern'],H['php_cgi_target_pattern']())
        expr=self.expression();disabled=self.expression(enabled=False);other=self.expression(['env'])
        with patch.dict(GLOBALS,normal_paths=lambda:['/','/index.php','/clientarea.php','/checkout.php','/login']):
            for (record,ip,positive),p in zip(cases,result['lines']):
                self.assertEqual(self.hit(expr,record),ip,record)
                self.assertEqual(p['recognized'],positive,record)
                self.assertEqual(p['non_offensive'],H['non_offensive_line'](record),record)
                self.assertIsNone(self.hit(disabled,record))
                self.assertIsNone(self.hit(other,record))
                if positive:self.assertEqual(p['family'],'php-cgi-injection');self.assertFalse(p['non_offensive'])
        self.assertEqual(len(result['lines']),len(cases))
        self.assertIsNone(self.hit(expr,line('/index.php',tail=f'"{PAYLOAD}" "GET {PAYLOAD} HTTP/1.1"')))

    def test_narrow_candidate_validates_without_accepting_benign_421(self):
        text=H['sensitive_filter'](['php_cgi_probe'])
        # Pure existing validation creates only its private temp fixtures.
        with patch.dict(GLOBALS,normal_paths=lambda:['/','/index.php','/clientarea.php','/checkout.php','/login']):
            H['validate_filter'](text,[line(PAYLOAD)])
            with self.assertRaises(ValueError):
                H['validate_filter'](text,[line('/index.php')])
            self.assertFalse(H['non_offensive_line'](line(PAYLOAD)))
            self.assertTrue(H['non_offensive_line'](line('/index.php')))

    def test_limits_and_forged_prefix(self):
        expr=self.expression();start=time.monotonic()
        for n in (800,8192,16000):
            self.assertIsNone(self.hit(expr,line('/?'+'x'*n+'allow_url_include=1')))
        self.assertLess(time.monotonic()-start,1.0)
        self.assertIsNone(self.hit(expr,'prefix '+line(PAYLOAD)))
        self.assertEqual(self.hit(expr,line(PAYLOAD,tail='"203.0.113.1" "[client 203.0.113.2]"')),'198.51.100.77')

if __name__=='__main__':unittest.main()
