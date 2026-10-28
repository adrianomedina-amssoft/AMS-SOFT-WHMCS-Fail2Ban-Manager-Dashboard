import ipaddress
import hashlib
import os
from pathlib import Path
import runpy
import tempfile
import time
import unittest
from unittest.mock import patch

HELPER = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'setup' / 'amsfb-admin'))
GLOBALS = HELPER['main'].__globals__


class PrivilegedTests(unittest.TestCase):
    def test_read_budget_is_limited_and_never_applies_to_writes(self):
        with patch.dict(GLOBALS, signal=__import__('unittest.mock', fromlist=['Mock']).Mock()):
            for seconds in ('1', '43', '45'):
                self.assertEqual(HELPER['prepare_budget'](['--read-budget', seconds, 'health']), ['health'])
            for seconds in ('0', '46', '-1', '1.5', '01', '1;reboot'):
                with self.assertRaises(ValueError):
                    HELPER['prepare_budget'](['--read-budget', seconds, 'health'])
            for operation in ('ban', 'install-jail', 'install-filter', 'reload', 'sync-policy'):
                with self.assertRaisesRegex(ValueError, 'restricted'):
                    HELPER['prepare_budget'](['--read-budget', '1', operation])
        with self.assertRaises(HELPER['ReadBudgetExceeded']):
            HELPER['budget_expired'](None, None)
        self.assertFalse(issubclass(HELPER['ReadBudgetExceeded'], Exception))

    def test_read_budget_interrupts_slow_reader_without_becoming_filter_error(self):
        import signal
        previous = signal.getsignal(signal.SIGALRM)
        started = time.monotonic()
        try:
            with patch.dict(GLOBALS, run=lambda args: time.sleep(2)):
                command = HELPER['prepare_budget'](['--read-budget', '1', 'client-read', 'ping'])
                with self.assertRaises(HELPER['ReadBudgetExceeded']):
                    HELPER['main'](command)
            self.assertLess(time.monotonic() - started, 2)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def test_client_read_never_accepts_mutations_or_flags(self):
        calls = []
        with patch.dict(GLOBALS, run=lambda args: calls.append(args) or 'fixture status'):
            self.assertEqual(HELPER['main'](['client-read', 'status', 'fixture'])['output'], 'fixture status')
            for command in (['reload'], ['set', 'fixture', 'banip', '203.0.113.7'], ['status', '--all'], ['status', '../fixture']):
                with self.assertRaisesRegex(ValueError, 'Invalid read command'):
                    HELPER['main'](['client-read'] + command)
        self.assertEqual(calls, [['/usr/bin/fail2ban-client', 'status', 'fixture']])

    def test_loaded_filter_macro_roundtrip_is_exact(self):
        from fail2ban.server.failregex import FailRegex
        for dns in ('no', 'warn', 'yes'):
            original=r'^<HOST> - .*GET /\.env '
            expanded=FailRegex(original,useDns=dns).getRegex()
            def native(args):
                return {'failregex':[expanded], 'prefregex':None, 'ignoreregex':[], 'logpath':['/var/log/fixture']}[args[-1]]
            with patch.dict(GLOBALS,native_command=native):
                result=HELPER['main'](['jail-filter-state','fixture'])
                self.assertEqual(result['patterns'],[original])
                self.assertEqual(result['ignoreregex'],[])
                self.assertEqual(FailRegex(result['patterns'][0],useDns=dns).getRegex(),expanded)

    def test_loaded_filter_rejects_unknown_capture_and_flags(self):
        with patch.dict(GLOBALS,native_command=lambda args:[r'^203\.0\.113\.1 attack$']):
            with self.assertRaisesRegex(ValueError,'HOST expansion'):
                HELPER['main'](['jail-filter-state','fixture'])
        for name in ('--restart','../fixture','fixture;reboot'):
            with self.assertRaisesRegex(ValueError,'Invalid jail'):
                HELPER['main'](['jail-filter-state',name])

    def test_native_repair_refuses_stale_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'filter.d').mkdir();target=root/'filter.d/amsfb-fixture.conf';target.write_text('unchanged')
            with patch.dict(GLOBALS,ROOT=root):
                with self.assertRaisesRegex(ValueError,'concurrently'):
                    HELPER['replace_existing_filter']('amsfb-fixture','new','0'*64,[])
            self.assertEqual(target.read_text(),'unchanged')

    def test_native_repair_requires_root_caller(self):
        with patch.dict(os.environ,SUDO_UID='33'):
            with self.assertRaisesRegex(ValueError,'root CLI'):
                HELPER['replace_existing_filter']('amsfb-fixture','new','0'*64,[])

    def test_login_redirect_is_not_attack_proof(self):
        positive=self.positive('/index.php?rp=/login').replace('"GET ', '"POST ').replace(' 404 ', ' 302 ')
        text='[Definition]\nfailregex = ^<HOST> - .*"POST /index\\.php\\?rp=/login HTTP/1\\.1" 302\n'
        with self.assertRaisesRegex(ValueError,'legitimate'):
            HELPER['validate_filter'](text,[positive])

    def test_native_repair_rolls_back_on_reload_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'filter.d').mkdir();(root/'jail.d').mkdir()
            target=root/'filter.d/amsfb-fixture.conf';old='[Definition]\nfailregex = ^OLD <HOST>$\n';target.write_text(old)
            calls=[]
            def execute(args):
                calls.append(args)
                if args[-2:]==['reload','fixture'] and sum(c[-2:]==['reload','fixture'] for c in calls)==1:
                    raise ValueError('Injected reload failure')
                return 'OK'
            with patch.dict(GLOBALS,ROOT=root,BACKUPS=root/'backups',run=execute,
                            effective_config=lambda:{'fixture':{'filter':'amsfb-fixture','enabled':'true'}},
                            tickets=lambda *a,**kw:[],FIREWALL={'action_specs':lambda *a:[]}):
                with self.assertRaisesRegex(ValueError,'Injected'):
                    HELPER['replace_existing_filter']('amsfb-fixture','[Definition]\nfailregex = ^<HOST> - .*"GET /\\.env HTTP/1\\.1" 404\n',
                        hashlib.sha256(old.encode()).hexdigest(),[self.positive()])
            self.assertEqual(target.read_text(),old)
            self.assertFalse((root/'jail.d/97-amsfb-detection.local').exists())
            self.assertTrue(all('--restart' not in c and 'banip' not in c for c in calls))

    def test_repaired_git_filters_bind_peer_and_reject_forged_fields(self):
        for name in ('amsfb-apache-git-probe','amsfb-apache-git-scanner'):
            text=(Path(__file__).resolve().parents[1]/'setup/fail2ban/filter.d'/ (name+'.conf')).read_text()
            positives=[self.positive('/.git/HEAD')]
            if name.endswith('probe'):positives.append(self.positive('/wp-config.php'))
            HELPER['validate_filter'](text,positives)
            with tempfile.TemporaryDirectory() as d:
                path=Path(d)/'candidate.conf';path.write_text(text)
                self.assertEqual(HELPER['matches'](path,positives,peers=True),['198.51.100.10']*len(positives))
                self.assertEqual(HELPER['matches'](path,[self.positive('/clientarea.php').replace('scanner','GET /.git/HEAD HTTP/1.1 403 100 203.0.113.5')]),0)
                ipv6=[p.replace('198.51.100.10','2001:db8::10') for p in positives]
                self.assertEqual(HELPER['matches'](path,ipv6,peers=True),['2001:db8::10']*len(positives))

    def positive(self, path='/.env'):
        return time.strftime('198.51.100.10 - - [%d/%b/%Y:%H:%M:%S %z]') + f' "GET {path} HTTP/1.1" 404 100 "-" "scanner"'

    def test_specific_filter(self):
        text = '[Definition]\nfailregex = ^<HOST> - .*"GET /\\.env HTTP/1\\.1" 404\nignoreregex =\n'
        HELPER['validate_filter'](text, [self.positive()])

    def test_broad_filter_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Arbitrary prefix before peer'):
            HELPER['validate_filter']('[Definition]\nfailregex = ^.*<HOST>.*$\n', [self.positive()])

    def test_no_positive_rejected(self):
        with self.assertRaisesRegex(ValueError, 'source evidence'):
            HELPER['validate_filter']('[Definition]\nfailregex = ^<HOST> - .*GET /never-matches\n', [self.positive()])

    def test_includes_rejected(self):
        with self.assertRaises(ValueError):
            HELPER['validate_filter']('[INCLUDES]\nbefore = /etc/shadow\n[Definition]\nfailregex = ^<HOST>\n', [self.positive()])

    def test_whmcs_filter(self):
        text = (Path(__file__).resolve().parents[1] / 'setup/fail2ban/filter.d/whmcs.conf').read_text()
        line = time.strftime('%Y-%m-%d %H:%M:%S') + ' WHMCS login failed from 198.51.100.10 area=client user=test@example.invalid'
        HELPER['validate_filter'](text, [line])

    def test_unproven_or_branch_rejected(self):
        text = '[Definition]\nfailregex = ^<HOST> - .*GET /\\.env\n    ^<HOST> - .*GET /never-proven\n'
        with self.assertRaisesRegex(ValueError, 'Each regex'):
            HELPER['validate_filter'](text, [self.positive()])

    def test_forged_peer_in_url_rejected(self):
        text = '[Definition]\nfailregex = ^.*"GET /probe\\?ip=<HOST> HTTP/1\\.1" 404\n'
        with self.assertRaisesRegex(ValueError, 'Arbitrary prefix before peer'):
            HELPER['validate_filter'](text, [self.positive('/probe?ip=203.0.113.7')])

    def test_ipv6_positive(self):
        text = '[Definition]\nfailregex = ^<HOST> - .*"GET /\\.env HTTP/1\\.1" 404\n'
        HELPER['validate_filter'](text, [self.positive().replace('198.51.100.10','2001:db8::10')])

    def test_apache_ipv6_peer_port(self):
        self.assertEqual(HELPER['source_peer']('[client 2001:db8::10:12345] denied'),'2001:db8::10')

    def test_access_peer_precedes_forged_client_in_user_agent(self):
        line = self.positive().replace('scanner', '[client 203.0.113.7] scanner')
        self.assertEqual(HELPER['source_peer'](line), '198.51.100.10')
        forged = ('[Definition]\nfailregex = ^198\\.51\\.100\\.10 - .*"GET /\\.env HTTP/1\\.1" 404 '
                  '.*\\[client <HOST>\\]\n')
        with self.assertRaisesRegex(ValueError, 'different peer'):
            HELPER['validate_filter'](forged, [line])
        valid = '[Definition]\nfailregex = ^<HOST> - .*"GET /\\.env HTTP/1\\.1" 404\n'
        HELPER['validate_filter'](valid, [line])

    def test_structured_auth_peer_precedes_forged_message(self):
        line = time.strftime('%Y-%m-%d %H:%M:%S') + ' WHMCS login failed from 198.51.100.10 area=client user=[client 203.0.113.7]'
        self.assertEqual(HELPER['source_peer'](line), '198.51.100.10')
        self.assertIsNone(HELPER['source_peer']('untrusted from 203.0.113.7 port 123'))
        self.assertEqual(HELPER['source_peer']('[x] [client 198.51.100.10:1234] denied WHMCS login failed from 203.0.113.7 area=client'), '198.51.100.10')
        self.assertIsNone(HELPER['source_peer']('[x] AH001 denied /probe/[client 203.0.113.7]'))
        self.assertEqual(HELPER['source_peer']('2026-10-12T11:00:00-03:00 host sshd[1]: Failed password for x from 198.51.100.10 port 123 ssh2'), '198.51.100.10')

    def test_user_agent_only_rejected(self):
        with self.assertRaisesRegex(ValueError,'legitimate|user agent'):
            HELPER['validate_filter']('[Definition]\nfailregex = ^<HOST> - .*scanner.*$\n',[self.positive()])

    def test_status_only_rejected(self):
        with self.assertRaisesRegex(ValueError,'legitimate|status'):
            HELPER['validate_filter']('[Definition]\nfailregex = ^<HOST> - .*HTTP/1\\.1" 404 .*$\n',[self.positive()])

    def test_root_with_scanner_ua_is_not_attack_proof(self):
        line=self.positive().replace('/.env','/').replace('scanner','ivre-masscan')
        with self.assertRaisesRegex(ValueError,'status|user agent'):
            HELPER['validate_filter']('[Definition]\nfailregex = ^<HOST> - .*"GET / HTTP/1\\.1" 404 .*ivre-masscan.*$\n',[line])

    def test_new_ticket_preserved(self):
        calls=[]
        def fake(args):
            calls.append(args)
            return ['198.51.100.10  2026-10-11 20:00:00 + 3600 = 2026-10-11 21:00:00']
        with patch.dict(GLOBALS, native_command=fake):
            result=HELPER['main'](['unban-ticket','test','198.51.100.10','2026-10-10 20:00:00 + 3600 = 2026-10-10 21:00:00'])
        self.assertTrue(result['skipped'])
        self.assertEqual(len(calls),1)

    def test_same_ticket_unbanned_once(self):
        calls=[]
        ticket='2026-10-11 20:00:00 + 3600 = 2026-10-11 21:00:00'
        def fake(args):
            calls.append(args)
            return ['198.51.100.10  '+ticket] if len(calls)==1 else 1
        with patch.dict(GLOBALS, native_command=fake):
            self.assertFalse(HELPER['main'](['unban-ticket','test','198.51.100.10',ticket])['skipped'])
        self.assertEqual(calls[-1][-2:],['unbanip','198.51.100.10'])

    def test_archive_integrity_and_immutable_parts(self):
        with tempfile.TemporaryDirectory() as d:
            import hashlib
            source=Path('/tmp')/('amsfb_archive_fixture_'+str(os.getpid()))
            source.write_text('{"rows":[]}')
            try:
                with patch.dict(GLOBALS, BACKUPS=Path(d)):
                    result=HELPER['archive_part']('a'*32,'0',str(source))
                    self.assertEqual(result['sha256'],hashlib.sha256(source.read_bytes()).hexdigest())
                    self.assertEqual(HELPER['verify_archive']('a'*32,[result])['verified_parts'],1)
                    self.assertEqual(HELPER['archive_part']('a'*32,'0',str(source)),result)
                    source.write_text('{"rows":[1]}')
                    with self.assertRaisesRegex(ValueError,'different content'):
                        HELPER['archive_part']('a'*32,'0',str(source))
                    (Path(d)/('job-'+'a'*32)/'part-0.json.bakp').write_text('corrupt')
                    with self.assertRaises(ValueError):
                        HELPER['verify_archive']('a'*32,[result])
            finally:
                source.unlink()

    def test_bounded_unban_batch(self):
        targets=[{'jail':'test','ip':'198.51.100.10','ticket':'old'}]
        with patch.dict(GLOBALS,unban_ticket=lambda *args:{'success':True,'skipped':True}):
            self.assertTrue(HELPER['unban_batch'](targets)['results'][0]['skipped'])
        with self.assertRaises(ValueError):
            HELPER['unban_batch'](targets*101)
        with self.assertRaises(ValueError):
            HELPER['unban_batch']([dict(targets[0],command='arbitrary')])

    def test_partial_unban_batch_records_progress(self):
        def fake(jail,ip,ticket):
            if ip.endswith('.20'):raise ValueError('Fixture failure')
            return {'success':True,'skipped':False}
        targets=[{'jail':'test','ip':ip,'ticket':'old'} for ip in ['198.51.100.10','198.51.100.20']]
        with patch.dict(GLOBALS,unban_ticket=fake):
            result=HELPER['unban_batch'](targets)
        self.assertEqual(len(result['results']),1)
        self.assertIn('error',result)

    def test_monitor_completion_survives_unit_collection(self):
        with tempfile.TemporaryDirectory() as d:
            job='b'*32;folder=Path(d)/('job-'+job);folder.mkdir()
            (folder/'monitor.jsonl').write_text('{"timestamp":"start","missing_f2b_rules":0}\n{"monitor_complete":true}\n')
            with patch.dict(GLOBALS,BACKUPS=Path(d),run=lambda args:'ActiveState=inactive\nLoadState=not-found\n'):
                result=HELPER['monitor'](job)
            self.assertTrue(result['completed'])
            self.assertEqual(result['samples'],1)

    def test_monitor_distinguishes_coverage_versions(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            job='c'*32;folder=Path(d)/('job-'+job);folder.mkdir()
            rows=[{'timestamp':'old','coverage_version':2,'missing_jail_tickets':0},
                  {'timestamp':'review','coverage_version':3,'missing_jail_tickets':0},
                  {'timestamp':'new','coverage_version':4,'missing_jail_tickets':1,'jails_without_actions':['test']},
                  {'monitor_complete':True}]
            (folder/'monitor.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
            with patch.dict(GLOBALS,BACKUPS=Path(d),run=lambda args:'ActiveState=inactive\nLoadState=not-found\n'):
                result=HELPER['monitor'](job)
            self.assertTrue(result['completed'])
            self.assertEqual(result['coverage_versions_seen'],[2,3,4])
            self.assertEqual(result['coverage_samples'],3)
            self.assertEqual(result['max_missing_jail_tickets'],1)
            self.assertEqual(result['jails_without_actions_seen'],['test'])

    def test_duration_change_never_alters_existing_tickets(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'jail.d').mkdir();(root/'filter.d').mkdir()
            with patch.dict(GLOBALS,ROOT=root,effective_config=lambda:{'ai-bans':{'bantime':'3600'}},
                            tickets=lambda *args,**kwargs:[{'ip':'198.51.100.10','ticket':'old'}]):
                with self.assertRaisesRegex(ValueError,'Bans ativos'):
                    HELPER['ensure_ai_jail']('7200')
            self.assertFalse((root/'jail.d/zz-amsfb-ai.local').exists())

    def test_unused_filter_preserves_disabled_consumers(self):
        with patch.dict(GLOBALS,effective_config=lambda:{'quarantined':{'enabled':'false','filter':'amsfb-used'}}):
            self.assertFalse(HELPER['main'](['quarantine-filter','used'])['success'])

    def test_unused_filter_is_backed_up(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'filter.d').mkdir();source=root/'filter.d/amsfb-unused.conf';source.write_text('fixture')
            with patch.dict(GLOBALS,ROOT=root,BACKUPS=root/'backups',effective_config=lambda:{}):
                self.assertTrue(HELPER['main'](['quarantine-filter','unused'])['quarantined'])
            self.assertFalse(source.exists())
            self.assertEqual(next((root/'backups').iterdir()).read_text(),'fixture')

    def test_default_action_change_rejected(self):
        with self.assertRaisesRegex(ValueError, 'DEFAULT'):
            HELPER['validate_jail']('[DEFAULT]\naction = safe\n', '[DEFAULT]\naction = unsafe\n')

    def test_reload_bridge_forbids_options_and_extra_arguments(self):
        calls = []
        with patch.dict(GLOBALS, run=lambda args: calls.append(args) or 'OK'):
            self.assertTrue(HELPER['main'](['reload'])['success'])
            self.assertTrue(HELPER['main'](['reload', 'ai-bans'])['success'])
            for args in [['reload','--unban'], ['reload','--restart'], ['reload','test','--unban']]:
                with self.assertRaises(ValueError):
                    HELPER['main'](args)
        self.assertEqual(calls, [['/usr/bin/fail2ban-client','reload'], ['/usr/bin/fail2ban-client','reload','ai-bans']])

    def test_action_injection_rejected(self):
        with self.assertRaisesRegex(ValueError, 'firewall action'):
            HELPER['validate_jail']('[test]\nenabled = false\n', '[test]\nenabled = false\naction = arbitrary[actionstart=touch /tmp/exploit]\n')

    def test_sensitive_log_rejected(self):
        with self.assertRaisesRegex(ValueError, 'log path'):
            HELPER['validate_jail']('[test]\nenabled = false\n', '[test]\nenabled = false\nlogpath = /etc/shadow\n')

    def test_unsafe_temporary(self):
        with self.assertRaises(ValueError):
            HELPER['temporary']('/etc/passwd', 'amsfb_')
        with tempfile.TemporaryDirectory() as d:
            link = Path('/tmp') / ('amsfb_filter_link_' + str(os.getpid()))
            link.symlink_to(Path(d) / 'target')
            try:
                with self.assertRaises(OSError):
                    HELPER['temporary'](str(link), 'amsfb_filter_')
            finally:
                link.unlink()

    def test_atomic_backup(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / 'jail.local'
            dest.write_text('original')
            with patch.dict(GLOBALS, BACKUPS=Path(d) / 'backups'):
                HELPER['atomic_write'](dest, 'updated')
            self.assertEqual(dest.read_text(), 'updated')
            self.assertEqual(next((Path(d) / 'backups').iterdir()).read_text(), 'original')
            self.assertEqual(dest.stat().st_mode & 0o777, 0o644)

    def test_firewall_requires_own_reachable_chain(self):
        def fake(args):
            if args[-1] == 'protocol': return 'tcp'
            if args[-1] == 'port': return '0:65535'
            if args[-1] == 'actions':
                return 'The jail has actions:\niptables-multiport-test\n'
            if args[0].endswith('iptables-save'):
                return '-A INPUT -j f2b-test\n-A f2b-test -s 198.51.100.10/32 -j REJECT\n'
            return '<iptables> -I f2b-test 1 -s <ip> -j <blocktype>\n'
        with patch.dict(GLOBALS, run=fake):
            self.assertTrue(HELPER['check_ban']('test', '198.51.100.10')['applied'])
            self.assertFalse(HELPER['check_ban']('test', '198.51.100.20')['applied'])
        def unreachable(args):
            if args[-1] == 'protocol': return 'tcp'
            if args[-1] == 'port': return '0:65535'
            if args[-1] == 'actions':
                return 'The jail has actions:\niptables-multiport-test\n'
            return '-A f2b-test -s 198.51.100.10/32 -j REJECT\n' if args[0].endswith('iptables-save') else '<iptables> -I f2b-test 1 -s <ip> -j <blocktype>\n'
        with patch.dict(GLOBALS, run=unreachable):
            self.assertFalse(HELPER['check_ban']('test', '198.51.100.10')['applied'])

    def test_ipv6_firewall(self):
        def fake(args):
            if args[-1] == 'protocol': return 'tcp'
            if args[-1] == 'port': return '0:65535'
            if args[-1] == 'actions':
                return 'The jail has actions:\niptables-multiport-test\n'
            if args[0].endswith('tables-save'):
                self.assertTrue(args[0].endswith('ip6tables-save'))
                return '-A INPUT -j f2b-test\n-A f2b-test -s 2001:db8::10/128 -j DROP\n'
            return '<iptables> -I f2b-test 1 -s <ip> -j <blocktype>\n'
        with patch.dict(GLOBALS, run=fake):
            self.assertTrue(HELPER['check_ban']('test', '2001:db8::10')['applied'])

    def test_other_jail_does_not_cover_ticket(self):
        def fake(args):
            if args[-1]=='actions': return 'The jail has actions:\niptables-test\n'
            if args[-1]=='protocol': return 'tcp'
            if args[-1]=='port': return '0:65535'
            if args[0].endswith('tables-save'): return '-A INPUT -p tcp -j f2b-other\n-A f2b-other -s 198.51.100.10/32 -j DROP\n'
            return '<iptables> -I f2b-own 1 -s <ip> -j <blocktype>'
        with patch.dict(GLOBALS, run=fake):
            self.assertFalse(HELPER['check_ban']('test','198.51.100.10')['applied'])

    def test_partial_ports_do_not_cover_all_tcp(self):
        def fake(args):
            if args[-1]=='actions': return 'The jail has actions:\niptables-test\n'
            if args[-1]=='protocol': return 'tcp'
            if args[-1]=='port': return '0:65535'
            if args[0].endswith('tables-save'): return '-A INPUT -p tcp -m multiport --dports 80,443 -j f2b-test\n-A f2b-test -s 198.51.100.10/32 -j DROP\n'
            return '<iptables> -I f2b-test 1 -s <ip> -j <blocktype>'
        with patch.dict(GLOBALS, run=fake):
            self.assertFalse(HELPER['check_ban']('test','198.51.100.10')['applied'])

    def test_absent_actions_never_effective(self):
        with patch.dict(GLOBALS, run=lambda args: 'No actions for jail test' if args[-1]=='actions' else ''):
            self.assertFalse(HELPER['check_ban']('test','198.51.100.10')['applied'])

    def test_firewall_preceding_accept_and_return(self):
        import shlex
        covers = GLOBALS['FIREWALL']['covers']
        spec = {'chain': 'f2b-test', 'protocol': 'tcp', 'ranges': [(0,65535)]}
        base = ['-A INPUT -p tcp -j f2b-test', '-A f2b-test -s 198.51.100.10/32 -j REJECT']
        def covered(lines):
            return covers([shlex.split(line) for line in lines], spec, '198.51.100.10')
        self.assertTrue(covered(base))
        self.assertFalse(covered(['-A INPUT -j ACCEPT'] + base))
        self.assertFalse(covered(['-A INPUT -p tcp --dport 443 -j ACCEPT'] + base))
        self.assertFalse(covered([base[0], '-A f2b-test -j RETURN', base[1]]))
        self.assertFalse(covered(['-A INPUT -j trusted'] + base + ['-A trusted -j ACCEPT']))
        self.assertTrue(covered(['-A INPUT -p udp -j ACCEPT'] + base))
        self.assertTrue(covered(['-A INPUT -s 203.0.113.0/24 -j ACCEPT'] + base))
        self.assertTrue(covered(base + ['-A INPUT -j ACCEPT', '-A f2b-test -j RETURN']))

    def test_firewall_goto_return_cannot_attest_coverage(self):
        import shlex
        covers = GLOBALS['FIREWALL']['covers']
        spec = {'chain': 'f2b-test', 'protocol': 'tcp', 'ranges': [(0,65535)]}
        reject = '-A f2b-test -s 198.51.100.10/32 -j REJECT'
        cases = [
            ['-A INPUT -g skipped', '-A INPUT -p tcp -j f2b-test',
             '-A skipped -j RETURN', reject],
            ['-A INPUT -p tcp -j f2b-test', '-A f2b-test -g skipped',
             reject, '-A skipped -j RETURN'],
        ]
        for lines in cases:
            with self.subTest(lines=lines):
                self.assertFalse(covers([shlex.split(line) for line in lines], spec, '198.51.100.10'))
        # Ordinary jump/RETURN resumes INPUT and must still attest coverage.
        lines = ['-A INPUT -j skipped', '-A skipped -j RETURN',
                 '-A INPUT -p tcp -j f2b-test', reject]
        self.assertTrue(covers([shlex.split(line) for line in lines], spec, '198.51.100.10'))

    def test_privileged_ban_protects_local_addresses(self):
        for ip in ['127.0.0.1', '127.3.4.5', '0.0.0.1', '::1', '::ffff:127.0.0.1']:
            with self.assertRaisesRegex(ValueError, 'Protected'):
                HELPER['main'](['ban', 'test', ip])

    def test_privileged_ban_respects_native_whitelist(self):
        with patch.dict(GLOBALS, run=lambda args: 'Ignored:\n|- 203.0.113.0/24\n'):
            with self.assertRaisesRegex(ValueError, 'Whitelisted'):
                HELPER['main'](['ban', 'test', '203.0.113.7'])

    def test_shared_policy_preserves_native_ignores(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'jail.d').mkdir()
            (root / 'jail.conf').write_text('[DEFAULT]\nignoreip = 127.0.0.1\n[test]\nenabled = true\nignoreip = 198.51.100.0/24\n')
            with patch.dict(GLOBALS, ROOT=root, BACKUPS=root / 'backups', run=lambda args:'OK'):
                HELPER['sync_policy'](['203.0.113.7'])
            policy = HELPER['parse']((root / 'jail.d/zz-amsfb-safety.local').read_text())
            self.assertIn('198.51.100.0/24', policy.get('test','ignoreip'))
            self.assertIn('203.0.113.7/32', policy.get('test','ignoreip'))
            self.assertIn('::1/128', policy.get('test','ignoreip'))
            self.assertNotIn('%', policy.get('test','ignoreip'))


if __name__ == '__main__':
    unittest.main()
