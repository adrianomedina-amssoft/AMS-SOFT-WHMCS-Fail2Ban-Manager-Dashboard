"""Credential-only override, with the installed legacy include tree (no daemon writes)."""
import shutil
import tempfile
import unittest
from pathlib import Path
from fail2ban.client.filterreader import FilterReader
from fail2ban.server.filter import Filter
from fail2ban.server.datedetector import DateDetector

ROOT = Path(__file__).resolve().parents[1]

def load_options(base):
    reader = FilterReader('apache-auth','fixture',{},basedir=str(base))
    if not reader.read():
        raise RuntimeError('Cannot read Apache filter')
    reader.getOptions({})
    return reader.getCombined()

def make_filter(options):
    engine=Filter(None,useDns='no')
    engine.prefRegex=options['prefregex']
    for pattern in options['failregex'].splitlines():
        if pattern:engine.addFailRegex(pattern)
    for pattern in (options.get('ignoreregex') or '').splitlines():
        if pattern:engine.addIgnoreRegex(pattern)
    return engine

def captured(engine,line):
    detector=DateDetector();detector.addDefaultTemplate()
    match=detector.matchTime(line)[0]
    split=(line[:match.start(1)],line[match.start(1):match.end(1)],line[match.end(1):]) if match else (line,'','')
    return {str(row[1]) for row in engine.findFailure(split,1792562400)}

class ApacheAuthScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='amsfb-auth-scope-')
        base=Path(cls.temp.name)
        shutil.copytree('/etc/fail2ban/filter.d',base/'filter.d')
        shutil.copy2(ROOT/'setup/fail2ban/filter.d/apache-auth.local',base/'filter.d/apache-auth.local')
        cls.options=load_options(base)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def line(self,body,ip='198.51.100.77',port=True):
        prefix='[auth_basic:error] [pid 123:tid 124]' if port else '[error]'
        return '[Wed Oct 21 03:00:00.123456 2026] '+prefix+' [client '+ip+(':1234' if port else '')+'] '+body

    def test_positive_credentials_and_correct_peer(self):
        bodies=[
          'AH01617: user alice: authentication failure for "/private": Password Mismatch',
          'AH01618: user alice not found: /private',
          'AH01617: user alice authentication failure',
          'AH01617: user alice: password mismatch',
          "AH01790: Digest: user `alice' in realm `Restricted' authentication failure",
          "AH01790: Digest: user `alice' in realm `Restricted' not found",
          'AH01617: Basic: user alice: password mismatch',
        ]
        for ip in ('198.51.100.77','2001:db8::77'):
            for port in (True,False):
                for body in bodies:
                    with self.subTest(ip=ip,port=port,body=body):
                        self.assertEqual(captured(make_filter(self.options),self.line(body,ip,port)),{ip})

    def test_operational_authorization_and_public_assets_not_credentials(self):
        bodies=[
          'AH01630: client denied by server configuration: /var/www/html/',
          'AH01630: client denied by server configuration: /var/www/html/favicon.ico',
          'AH01630: client denied by server configuration: /var/www/html/clientarea.php',
          'AH01630: client denied by server configuration: /var/www/html/.env',
          'AH01630: client denied by server configuration: /var/www/html/druid',
          'AH02032: Hostname example.com provided via SNI, but no hostname provided in HTTP request',
          'AH02032: No hostname example.com provided via SNI and hostname other.example provided',
          'AH01631: user alice: authorization failure for "/private"',
          'AH01631: user alice denied by provider',
          'AH01631: Authorization of user alice to access /private failed',
          'AH01614: client used wrong authentication scheme',
          'AH01789: Digest: invalid nonce abc received - length is not valid',
          'AH00128: File does not exist: /var/www/html/missing',
        ]
        for ip in ('198.51.100.77','2001:db8::77'):
            for body in bodies:
                with self.subTest(ip=ip,body=body):
                    self.assertEqual(captured(make_filter(self.options),self.line(body,ip)),set())
            for path,status in (('/',403),('/clientarea.php',404),('/.env',404),('/templates/lagom2/assets/js/main.js',200)):
                line=ip+' - - [21/Oct/2026:03:00:00 -0300] "GET '+path+' HTTP/1.1" '+str(status)+' 10 "-" "fixture"'
                self.assertEqual(captured(make_filter(self.options),line),set())

    def test_complete_override_and_no_ignore_bypass(self):
        self.assertEqual(len(self.options['failregex'].splitlines()),3)
        self.assertFalse(self.options.get('ignoreregex'))
        body='AH01617: user alice: password mismatch [client 203.0.113.99:80] AH01630: client denied by server configuration'
        self.assertEqual(captured(make_filter(self.options),self.line(body)),{'198.51.100.77'})

    def test_modern_missing_port_is_not_ambiguous_authority(self):
        line=self.line('AH01617: user alice: password mismatch','2001:db8::77')
        self.assertEqual(captured(make_filter(self.options),line.replace('::77:1234]','::77]')),set())
        for port in ('1','22','1234','65535'):
            self.assertEqual(captured(make_filter(self.options),line.replace(':1234]',':'+port+']')),{'2001:db8::77'})

if __name__=='__main__':
    unittest.main()
