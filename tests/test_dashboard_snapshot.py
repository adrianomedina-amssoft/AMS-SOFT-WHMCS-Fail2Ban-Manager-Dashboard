import runpy
import functools
import ipaddress
import shlex
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

H = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'setup/amsfb-admin'))
G = H['main'].__globals__
F = H['FIREWALL']


class DashboardSnapshotTests(unittest.TestCase):
    def native(self, args):
        if args == ['status']: return [('Jail list', 'fixture')]
        if args == ['get', 'fixture', 'actions']: return ['iptables-multiport']
        values = {'actionban': '<iptables> -I f2b-fixture 1 -s <ip> -j REJECT', 'protocol': 'tcp', 'port': '80,443'}
        if args[:4] == ['get', 'fixture', 'action', 'iptables-multiport'] and len(args) == 5: return values[args[4]]
        raise AssertionError('Unexpected native command: ' + str(args))

    def test_action_parser_equivalence(self):
        def cli(args):
            value = self.native(args[1:])
            return 'The jail has the following actions:\n' + '\n'.join(value) if isinstance(value, list) else value
        with patch.dict(G, native_command=self.native, run=lambda a: self.fail('CLI forbidden')):
            self.assertEqual(H['native_action_specs']('fixture'), F['action_specs']('fixture', cli))

    def test_invalid_names_and_limits(self):
        for value in ['iptables', None, ['a', 'a'], ['a\n'], ['--evil'], ['x'*129], ['a'+str(i) for i in range(101)]]:
            with patch.dict(G, native_command=lambda a: value):
                with self.assertRaises(ValueError): H['native_action_specs']('fixture')
        with patch.dict(G, native_command=lambda a: self.fail('No read for invalid jail')):
            for jail in ['../a', '-a', 'a\n', '', None]:
                with self.assertRaises(ValueError): H['native_action_specs'](jail)

    def test_invalid_properties(self):
        for value in [None, [], 1, 'x'*16385, 'a\x00b']:
            with patch.dict(G, native_command=lambda a: ['iptables-multiport'] if a[-1]=='actions' else value):
                with self.assertRaises(ValueError): H['native_action_specs']('fixture')

    def test_empty_actions(self):
        with patch.dict(G, native_command=lambda a: []): self.assertEqual(H['native_action_specs']('fixture'), [])

    def test_unsupported_action(self):
        with patch.dict(G, native_command=lambda a: ['custom'] if a[-1]=='actions' else 'unknown action'):
            self.assertEqual(H['native_action_specs']('fixture'), [{'action':'custom','supported':False}])

    def snapshot(self, mode='ok', ip='198.51.100.1'):
        rules = [shlex.split('-A INPUT -p tcp -m multiport --dports 80,443 -j f2b-fixture'),
                 shlex.split('-A f2b-fixture -s '+ip+' -j REJECT'), shlex.split('-A f2b-fixture -j RETURN')]
        if mode == 'missing': rules.pop(1)
        if mode == 'bypass': rules.insert(0, shlex.split('-A INPUT -j ACCEPT'))
        ticket = {'jail':'fixture','ip':ip,'ticket':'2026-10-24 00:00:00 + -1 = permanent'}
        seen = {'tickets':0,'rules':0,'inventory':0}
        def tickets(*args, **kwargs):
            self.assertTrue(kwargs.get('native'));seen['tickets'] += 1
            return [] if mode == 'ticket_changed' and seen['tickets']>1 else [ticket]
        def read_rules(*args):
            seen['rules'] += 1
            return rules + [['changed']] if mode=='rules_changed' and seen['rules']>2 else rules
        def native(args):
            if mode=='timeout': raise H['ReadBudgetExceeded']('timeout')
            if args==['status']:
                seen['inventory']+=1
                if mode=='inventory_changed' and seen['inventory']>1: return [('Jail list','fixture, another')]
            if mode=='unsupported' and args[-1]=='actionban': return 'unsupported'
            if mode=='failure' and args[-1]=='actions': raise ValueError('read failure')
            return self.native(args)
        with patch.dict(G, native_command=native, tickets=tickets, effective_config=lambda:{},
                        FIREWALL=dict(F, read_rules=read_rules), run=lambda a:self.fail('No CLI in dashboard coverage')):
            return H['main'](['dashboard-protection-snapshot'])

    def test_real_firewall_predicate_ipv4_ipv6(self):
        for ip in ['198.51.100.1','2001:db8::1']:
            result=self.snapshot(ip=ip)
            self.assertTrue(result['success']);self.assertTrue(result['stable'])
            self.assertEqual(result['entries'][0]['ports'],[80,443]);self.assertEqual(result['entries'][0]['ip'],ip)

    def test_missing_rule_not_protected(self): self.assertEqual(self.snapshot('missing')['entries'],[])

    def test_earlier_accept_not_protected(self): self.assertEqual(self.snapshot('bypass')['entries'],[])

    def test_changing_snapshot(self):
        for mode in ['ticket_changed','rules_changed','inventory_changed']:
            result=self.snapshot(mode);self.assertFalse(result['success']);self.assertEqual(result['entries'],[])

    def test_unsupported_or_failure_not_success(self):
        for mode in ['unsupported','failure']:
            result=self.snapshot(mode);self.assertFalse(result['success']);self.assertTrue(result['errors'])

    def test_timeout_escapes(self):
        with self.assertRaises(H['ReadBudgetExceeded']): self.snapshot('timeout')

    def test_dispatch_is_scoped_and_no_arguments(self):
        calls=[]
        with patch.dict(G, ban_coverage=lambda *a,**kw:calls.append((a,kw))):
            H['main'](['dashboard-protection-snapshot']);H['main'](['protection-snapshot']);H['main'](['ban-coverage'])
            self.assertEqual(calls,[((),{'services':True,'native_actions':True}),((None,),{'services':True}),((None,),{})])
            with self.assertRaises(ValueError): H['main'](['dashboard-protection-snapshot','198.51.100.1'])
            self.assertEqual(len(calls),3)

    def test_budget_and_version(self):
        with patch.dict(G, signal=Mock()):
            self.assertEqual(H['prepare_budget'](['--read-budget','15','dashboard-protection-snapshot']),['dashboard-protection-snapshot'])
        self.assertEqual(H['main'](['health'])['version'],30)

    def test_cached_literal_parser_does_not_cache_rules(self):
        reader=functools.lru_cache(maxsize=4096)(ipaddress.ip_network)
        rules=[shlex.split('-A INPUT -p tcp --dport 80 -j f2b-fixture'),
               shlex.split('-A f2b-fixture -s 198.51.100.1/32 -j REJECT')]
        spec={'chain':'f2b-fixture','protocol':'tcp','ranges':[(80,80)]}
        for rows in [rules, rules[:1], [shlex.split('-A INPUT -j ACCEPT')]+rules]:
            self.assertEqual(F['covers'](rows,spec,'198.51.100.1'),F['covers'](rows,spec,'198.51.100.1',network_reader=reader))
        self.assertGreater(reader.cache_info().hits,0)
        self.assertFalse(F['covers'](rules[:1],spec,'198.51.100.1',network_reader=reader))

    def test_literal_cache_bounded_and_errors_remain_errors(self):
        reader=functools.lru_cache(maxsize=4096)(ipaddress.ip_network)
        for i in range(4200):reader('2001:db8::'+format(i,'x')+'/128')
        self.assertEqual(reader.cache_info().currsize,4096)
        for value in ['not-a-network','198.51.100.1/24']:
            with self.assertRaises(ValueError):reader(value)


if __name__ == '__main__': unittest.main()
