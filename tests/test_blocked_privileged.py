import datetime
import json
from pathlib import Path
import runpy
import shlex
import sys
import time
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1]
HELPER = runpy.run_path(str(MODULE / 'setup/amsfb-admin'))
GLOBALS = HELPER['main'].__globals__
REAL = HELPER['FIREWALL']


class BlockedReadTests(unittest.TestCase):
    def coverage(self, version=4, ports='80,443', missing=False, bypass=False, expires=3600):
        ip = '198.51.100.10' if version == 4 else '2001:db8::10'
        rules = [shlex.split('-A INPUT -p tcp -m multiport --dports '+ports+' -j f2b-fixture'),
                 shlex.split('-A f2b-fixture -s '+ip+' -j REJECT'),
                 shlex.split('-A f2b-fixture -j RETURN')]
        if missing:
            rules = rules[:1] + rules[2:]
        if bypass:
            rules.insert(0, shlex.split('-A INPUT -j ACCEPT'))
        end = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()+expires))
        ticket = {'jail':'fixture','ip':ip,'ticket':'2026-10-13 00:00:00 + '+str(expires)+' = '+end}
        firewall = dict(REAL, read_rules=lambda *args: rules,
                        action_specs=lambda *args:[{'supported':True,'protocol':'tcp','ranges':REAL['ranges'](ports),'chain':'f2b-fixture'}])
        with patch.dict(GLOBALS, native_command=lambda args:[('Jail list','fixture')],
                        tickets=lambda *args,**kw:[ticket], FIREWALL=firewall):
            return HELPER['main'](['ban-coverage'])

    def test_real_rule_reader_confirms_ipv4_ipv6(self):
        for version in (4, 6):
            result = self.coverage(version)
            self.assertTrue(result['success'])
            self.assertEqual(result['entries'][0]['ports'],[80,443])
            self.assertTrue(result['entries'][0]['effective'])

    def test_ticket_without_reject_is_not_protection(self):
        self.assertEqual(self.coverage(missing=True)['entries'],[])

    def test_earlier_accept_refuses_coverage(self):
        self.assertEqual(self.coverage(bypass=True)['entries'],[])

    def test_ssh_scope_does_not_protect_http(self):
        self.assertEqual(self.coverage(ports='22')['entries'],[])

    def test_expired_ticket_is_not_protection(self):
        self.assertEqual(self.coverage(expires=-60)['entries'],[])

    def test_evidence_preparation_preserves_originals(self):
        original = '198.51.100.10 - - [13/Oct/2026:04:14:31 -0300] "GET /.env HTTP/1.1" 403 1 "-" "scanner"'
        error = '[Tue Oct 13 07:20:28.325818 2026] [authz_core:error] [pid 1:tid 1] [client 198.51.100.10:6000] AH01630: client denied by server configuration: /var/www/.env'
        result = HELPER['prepare_evidence']([original,error])
        lines = list(result['lines'].values())
        self.assertIn(' - - [] "GET /.env ',lines[0])
        self.assertTrue(lines[1].startswith('[] [authz_core:error]'))
        self.assertIn('[13/Oct/2026:',original)
        text = '[Definition]\nfailregex = ^<HOST> - \\S+ \\[\\s*\\] "GET /\\.env HTTP/1\\.1" 403 \\S+\nignoreregex =\n'
        HELPER['validate_filter'](text,[original])

    def test_invalid_evidence_shapes_are_refused(self):
        for lines in ({'line':'bad'},[1],['x'*65536]):
            with self.assertRaises(ValueError):
                HELPER['prepare_evidence'](lines)

    def test_error_detail_has_stage_and_no_control_characters(self):
        sys.path.insert(0,str(MODULE / 'scripts'))
        audit=runpy.run_path(str(MODULE / 'scripts/audit.py'))
        error=audit['AuditFailure']('ticket_parse','fixture',ValueError('invalid\naddress'))
        self.assertEqual(error.stage,'ticket_parse')
        self.assertEqual(error.jail,'fixture')
        self.assertNotIn('\n',error.detail)

    def test_repaired_env_filter_rejects_forged_peer_and_legitimate_paths(self):
        text=(MODULE/'setup/fail2ban/filter.d/amsfb-apache-env-probe.conf').read_text()
        original='198.51.100.143 - - [13/Oct/2026:04:14:31 -0300] "GET /.env HTTP/1.1" 403 4369 "-" "Mozilla/5.0"'
        HELPER['validate_filter'](text,[original])
        for version in ('198.51.100.10','2001:db8::10'):
            HELPER['validate_filter'](text,[original.replace('198.51.100.143',version)])


if __name__ == '__main__':
    unittest.main()
