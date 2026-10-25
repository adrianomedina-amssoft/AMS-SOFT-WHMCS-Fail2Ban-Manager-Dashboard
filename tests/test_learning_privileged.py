import hashlib
import os
from pathlib import Path
import runpy
import tempfile
import time
import unittest
from unittest.mock import patch

HELPER=runpy.run_path(str(Path(__file__).resolve().parents[1]/'setup/amsfb-admin'))
G=HELPER['main'].__globals__

class LearningTests(unittest.TestCase):
    def line(self,target='/wp-admin/',agent='agent'):
        return f'203.0.113.7 - - [{time.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {target} HTTP/1.1" 403 10 "-" "{agent}"'

    def test_timestamp_only_normalization(self):
        pattern=r'^<HOST> - \S+ \[[^]]+\] "GET /wp-admin/ HTTP/1\.1" 403 \S+'
        result=HELPER['normalize_evidence_filter']({'patterns':[pattern],'evidence':[self.line()]})
        self.assertTrue(result['changed']);self.assertIn(r'\[\s*\]',result['patterns'][0])

    def test_normalization_does_not_fix_wrong_target(self):
        with self.assertRaises(ValueError):
            HELPER['normalize_evidence_filter']({'patterns':[r'^<HOST> - \S+ \[[^]]+\] "GET /other HTTP/1\.1" 403 \S+'],'evidence':[self.line()]})

    def test_ordinary_compatible_browser_rejected(self):
        with self.assertRaises(ValueError):
            HELPER['validate_filter']('[Definition]\nfailregex = ^<HOST> - .* "GET / HTTP/1\\.1" \\d+ \\d+ "-" "Mozilla/5\\.0 \\(compatible\\)"\nignoreregex =\n',[self.line('/','Mozilla/5.0 (compatible)')])

    def test_extension_requires_root_worker(self):
        with patch.dict(os.environ,{'SUDO_UID':'33'}):
            with self.assertRaisesRegex(ValueError,'root worker'):HELPER['extend_managed_rule']({})

    def test_extension_refuses_quarantine(self):
        with patch.dict(os.environ,{'SUDO_UID':'0'}),patch.dict(G,effective_config=lambda:{'amsfb-test':{'enabled':'true','filter':'amsfb-test'}},loaded_filter_state=lambda j:{'prefregex':None,'ignoreregex':[],'patterns':['^(?!)<HOST>$']}):
            with self.assertRaisesRegex(ValueError,'Quarantined'):HELPER['extend_managed_rule']({'jail':'amsfb-test','filter':'amsfb-test'})

    def test_ticket_preservation_is_scoped_by_jail(self):
        ticket={'jail':'amsfb-test','ip':'203.0.113.7','ticket':'x = '+time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()+600))}
        seen=[]
        def tickets(jails,native=False):seen.extend(jails);return [ticket]
        with patch.dict(G,tickets=tickets):HELPER['verify_preserved_tickets']([ticket])
        self.assertEqual(seen,['amsfb-test'])

    def test_invalid_regex_never_becomes_coverage(self):
        state={'prefregex':None,'ignoreregex':[],'patterns':[r'^.*<HOST>.*InternetMeasurement/'],'paths':[]}
        with patch.dict(G,loaded_filter_state=lambda j:state):
            with self.assertRaises(ValueError):HELPER['filter_coverage']('amsfb-test',[self.line(agent='InternetMeasurement/ 203.0.113.77')])

    def test_gateway_sources_are_explicit(self):
        self.assertIn('/var/log/apache2/access_license_gateway.log',HELPER['APPROVED_SOURCES'])
        self.assertNotIn('/var/log/arbitrary.log',HELPER['APPROVED_SOURCES'])

    def test_error_body_cannot_replace_structured_peer(self):
        line='['+time.strftime('%a %b %d %H:%M:%S %Y')+'] [authz_core:error] [pid 123:tid 456] [client 203.0.113.7:12345] AH01630: client denied by server configuration: /var/www/wp-includes/test.php'
        bad=r'^.* \[client <HOST>:\d+\] AH01630: client denied by server configuration: .*wp-includes.*'
        with self.assertRaises(ValueError):HELPER['validate_filter']('[Definition]\nfailregex = '+bad+'\nignoreregex =\n',[line])
        good=r'^\[\s*\]\s+\[[^\]\r\n]+\]\s+(?:\[pid [^\]\r\n]+\]\s+)?\[client <HOST>:\d+\] AH01630: client denied by server configuration: .*wp-includes.*'
        HELPER['validate_filter']('[Definition]\nfailregex = '+good+'\nignoreregex =\n',[line])

if __name__=='__main__':unittest.main()
