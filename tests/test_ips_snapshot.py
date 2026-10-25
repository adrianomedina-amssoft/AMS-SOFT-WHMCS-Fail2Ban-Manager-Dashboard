import copy
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

H = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'setup/amsfb-admin'))
G = H['main'].__globals__


class IpsSnapshotTests(unittest.TestCase):
    def fixture(self, mode='ok', peers=None):
        calls = []
        peers = peers if peers is not None else ['198.51.100.1', '2001:db8::1']
        counts = {'inventory': 0, 'status': 0, 'ticket': 0}
        def native(args):
            calls.append(args)
            if args == ['status']:
                counts['inventory'] += 1
                names = ['a', 'b']
                if mode == 'empty':
                    names = []
                if mode == 'inventory_changed' and counts['inventory'] > 1:
                    names = ['a']
                if mode == 'duplicate_names':
                    names = ['a', 'a']
                if mode == 'invalid_name':
                    names = ['--unban']
                if mode == 'too_many_jails':
                    names = ['j' + str(i) for i in range(201)]
                value = [('Number of jail', len(names)), ('Jail list', ', '.join(names))]
                if mode == 'wrong_count':
                    value[0] = ('Number of jail', 3)
                if mode == 'boolean_count':
                    value[0] = ('Number of jail', True)
                if mode == 'duplicate_field':
                    value += [('Jail list', 'a, b')]
                return value
            jail = args[1]
            current = peers if jail == 'a' else []
            if mode == 'timeout':
                raise H['ReadBudgetExceeded']('fixture timeout')
            if mode == 'partial' and jail == 'a':
                raise RuntimeError('fixture read failure')
            if args[0] == 'status' and len(args) == 2:
                if jail == 'a':
                    counts['status'] += 1
                value = [('Filter', [('Currently failed', 0), ('Total failed', 1)]),
                         ('Actions', [('Currently banned', len(current)), ('Total banned', 5), ('Banned IP list', current)])]
                if jail == 'a':
                    if mode == 'wrong_status_count':
                        value[1][1][0] = ('Currently banned', 100)
                    if mode == 'negative_counter':
                        value[0][1][0] = ('Currently failed', -1)
                    if mode == 'boolean_counter':
                        value[0][1][0] = ('Currently failed', False)
                    if mode == 'status_changed' and counts['status'] > 1:
                        value[1][1][0] = ('Currently banned', 0)
                        value[1][1][2] = ('Banned IP list', [])
                return value
            if args == ['get', jail, 'banip', '--with-time']:
                if jail == 'a':
                    counts['ticket'] += 1
                if mode == 'expired' and jail == 'a':
                    return []
                duration = '-1 = permanent'
                if mode == 'renewed' and counts['ticket'] > 1:
                    duration = '3600 = renewed'
                if mode == 'invalid_identity':
                    duration = 'bad\x00identity'
                if mode == 'long_identity':
                    duration = 'x' * 201
                return [ip + '  2026-10-24 00:00:00 + ' + duration for ip in current]
            raise AssertionError('Unexpected command: ' + str(args))
        return native, calls

    def execute(self, mode='ok', peers=None):
        native, calls = self.fixture(mode, peers)
        with patch.dict(G, native_command=native, run=lambda args: self.fail('No subprocess allowed')):
            result = H['main'](['ips-snapshot'])
        return result, calls

    def test_stable_inventory_and_temporal_identity(self):
        result, calls = self.execute()
        self.assertTrue(result['complete'])
        self.assertTrue(result['inventory_stable'])
        self.assertEqual(result['names'], ['a', 'b'])
        self.assertEqual(len(result['targets']), 2)
        self.assertIn('+ -1 = permanent', result['targets'][0]['ticket'])
        self.assertEqual(len(calls), 10)  # two inventories + four read commands per jail
        self.assertTrue(all(c[0] in ('status', 'get') for c in calls))

    def test_empty_is_measured_not_unknown(self):
        result, calls = self.execute('empty')
        self.assertTrue(result['complete'])
        self.assertEqual(result['names'], [])
        self.assertEqual(result['targets'], [])
        self.assertEqual(len(calls), 2)

    def test_partial_preserves_only_verified_jails(self):
        result, _ = self.execute('partial')
        self.assertFalse(result['complete'])
        self.assertIsNone(result['statuses']['a'])
        self.assertEqual(result['errors'], ['a'])
        self.assertEqual(result['targets'], [])
        self.assertEqual(result['statuses']['b']['currently_banned'], 0)

    def test_changed_inventory_discards_all_rows(self):
        result, _ = self.execute('inventory_changed')
        self.assertFalse(result['inventory_stable'])
        self.assertFalse(result['complete'])
        self.assertEqual(result['statuses'], {})
        self.assertEqual(result['targets'], [])

    def test_expired_ticket_is_not_confirmed(self):
        result, _ = self.execute('expired')
        self.assertIsNone(result['statuses']['a'])
        self.assertEqual(result['targets'], [])

    def test_renewed_identity_is_not_confirmed(self):
        result, _ = self.execute('renewed')
        self.assertIsNone(result['statuses']['a'])
        self.assertFalse(result['complete'])

    def test_membership_changed_is_not_confirmed(self):
        result, _ = self.execute('status_changed')
        self.assertIsNone(result['statuses']['a'])

    def test_invalid_native_inventory(self):
        for mode in ('duplicate_names', 'invalid_name', 'too_many_jails', 'wrong_count', 'boolean_count', 'duplicate_field'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.execute(mode)

    def test_invalid_native_counter(self):
        for mode in ('negative_counter', 'boolean_counter', 'wrong_status_count'):
            with self.subTest(mode=mode):
                result, _ = self.execute(mode)
                self.assertFalse(result['complete'])
                self.assertIsNone(result['statuses']['a'])

    def test_invalid_temporal_identity(self):
        for mode in ('invalid_identity', 'long_identity'):
            result, _ = self.execute(mode)
            self.assertIsNone(result['statuses']['a'])
            self.assertEqual(result['targets'], [])

    def test_duplicate_or_invalid_ip(self):
        for peers in (['198.51.100.1'] * 2, ['198.51.100.1/24'], ['not-an-ip']):
            result, _ = self.execute(peers=peers)
            self.assertFalse(result['complete'])
            self.assertIsNone(result['statuses']['a'])

    def test_ipv6_normalization_and_mapped_peer(self):
        result, _ = self.execute(peers=['2001:0DB8:0:0::1', '::ffff:198.51.100.1'])
        self.assertTrue(result['complete'])
        self.assertEqual(result['statuses']['a']['banned_ip_list'], ['2001:db8::1', '::ffff:c633:6401'])

    def test_snapshot_limit(self):
        native, _ = self.fixture()
        huge = [{'jail': 'a', 'ip': '198.51.100.1', 'ticket': 'x'}] * 50001
        with patch.dict(G, native_command=native, tickets=lambda *a, **k: huge):
            result = H['main'](['ips-snapshot'])
        self.assertFalse(result['complete'])
        self.assertEqual(result['targets'], [])

    def test_timeout_escapes_partial_handler(self):
        with self.assertRaises(H['ReadBudgetExceeded']):
            self.execute('timeout')

    def test_no_caller_arguments_accepted(self):
        with patch.dict(G, native_command=lambda args: self.fail('No native command')):
            for args in (['ips-snapshot', 'a'], ['ips-snapshot', '--unban'], ['ips-snapshot', '/tmp/input']):
                with self.assertRaises(ValueError):
                    H['main'](args)

    def test_read_budget_and_helper_version(self):
        self.assertIn('ips-snapshot', H['READ_OPERATIONS'])
        with patch.dict(G, signal=unittest.mock.Mock()):
            self.assertEqual(H['prepare_budget'](['--read-budget','5','ips-snapshot']), ['ips-snapshot'])
        self.assertEqual(H['main'](['health']), {'success':True, 'version':30})


if __name__ == '__main__':
    unittest.main()
