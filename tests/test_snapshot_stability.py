import importlib.machinery
import importlib.util
import pathlib
import time
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[1] / 'setup' / 'amsfb-admin'
loader = importlib.machinery.SourceFileLoader('amsfb_snapshot_fixture', str(PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
bridge = importlib.util.module_from_spec(spec)
loader.exec_module(bridge)


class SnapshotTests(unittest.TestCase):
    def snapshot(self, changing_ticket=False, changing_rules=False, custom_ssh=False):
        ticket = {'jail': 'fixture', 'ip': '198.51.100.7',
                  'ticket': '2026-10-14 00:00:00 + -1 = permanent'}
        calls = {'tickets': 0, 'rules': 0}
        def tickets(*args, **kwargs):
            calls['tickets'] += 1
            return [] if changing_ticket and calls['tickets'] > 1 else [ticket]
        def rules(*args):
            calls['rules'] += 1
            return [['changed']] if changing_rules and calls['rules'] > 2 else []
        firewall = dict(bridge.FIREWALL)
        firewall.update(read_rules=rules, action_specs=lambda *a: [
            {'supported': True, 'protocol': 'tcp', 'ranges': [(0, 65535)]}],
            covers=lambda *a: True, ranges=lambda *a: [(2222, 2222)])
        with (
            mock.patch.object(bridge, 'tickets', tickets),
            mock.patch.object(bridge, 'FIREWALL', firewall),
            mock.patch.object(bridge, 'native_command', lambda *a: [('Jail list', 'fixture')]),
            mock.patch.object(bridge, 'effective_config', lambda: {'fixture': {'filter': 'sshd', 'port': '2222'}}),
        ):
            return bridge.ban_coverage(services=custom_ssh)
    def test_stable_ticket_rule(self):
        result = self.snapshot()
        self.assertTrue(result['success'])
        self.assertTrue(result['stable'])
        self.assertEqual(result['entries'][0]['ports'], [80, 443])
    def test_ticket_changed(self):
        result = self.snapshot(changing_ticket=True)
        self.assertFalse(result['success'])
        self.assertEqual(result['entries'], [])
    def test_rules_changed(self):
        self.assertFalse(self.snapshot(changing_rules=True)['stable'])
    def test_configured_ssh_scope(self):
        result = self.snapshot(custom_ssh=True)
        self.assertEqual(result['requirements']['ssh'], [2222])
        self.assertEqual(result['entries'][0]['ports'], [80, 443, 2222])

if __name__ == '__main__':
    unittest.main()
