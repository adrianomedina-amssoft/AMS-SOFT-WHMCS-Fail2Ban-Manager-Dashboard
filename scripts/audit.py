#!/usr/bin/python3
"""Read-only daemon/firewall reconciliation; optional bounded monitoring."""
import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import re
import shlex
import subprocess
import time
from firewall_state import inspect, read_rules, READER_REVISION


class AuditFailure(Exception):
    def __init__(self, stage, jail, exc):
        self.stage, self.jail, self.kind = stage, jail, type(exc).__name__
        # No command output, raw logs, credentials or response bodies.
        self.detail = re.sub(r'[\r\n\x00-\x1f]', ' ', str(exc))[:240]
        super().__init__(self.detail)


def command(args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=30)
    except Exception as exc:
        jail = args[2] if len(args)>2 and args[1] in ('get', 'status') else None
        raise AuditFailure('native_command', jail, exc) from exc


def snapshot():
    status = command(['/usr/bin/fail2ban-client', 'status'])
    match = re.search(r'Jail list:\s*(.*)', status)
    jails = match.group(1).split(', ') if match and match.group(1).strip() else []

    def inspect_jail(jail):
        try:
            text = command(['/usr/bin/fail2ban-client', 'status', jail])
            found = re.search(r'Banned IP list:\s*(.*)', text)
            return {str(ipaddress.ip_address(ip)) for ip in found.group(1).split()} if found else set()
        except AuditFailure:
            raise
        except Exception as exc:
            raise AuditFailure('ticket_parse', jail, exc) from exc

    def coverage(pair):
        try:
            return inspect(pair[0], pair[1], command, dict(rules))
        except AuditFailure:
            raise
        except Exception as exc:
            raise AuditFailure('jail_coverage', pair[0], exc) from exc

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        sets = list(pool.map(inspect_jail, jails))
    rules = {v: read_rules(command, v) for v in (4, 6)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        details = list(pool.map(coverage, zip(jails, sets)))
    reported = set().union(*sets) if sets else set()
    protected = set()
    for version_rules in rules.values():
        reachable = {r[r.index('-j')+1] for r in version_rules if r[1] == 'INPUT' and '-j' in r and r[r.index('-j')+1].startswith('f2b-')}
        for rule in version_rules:
            if rule[1] in reachable and '-s' in rule and '-j' in rule and rule[rule.index('-j')+1] in ('DROP','REJECT'):
                network = ipaddress.ip_network(rule[rule.index('-s')+1])
                if network.prefixlen == network.max_prefixlen:
                    protected.add(str(network.network_address))
                else:
                    protected.update(ip for ip in reported if ipaddress.ip_address(ip).version == network.version and ipaddress.ip_address(ip) in network)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        after_sets = list(pool.map(inspect_jail, jails))
    after_rules = {v: read_rules(command, v) for v in (4, 6)}
    after_status = command(['/usr/bin/fail2ban-client', 'status'])
    after_names = re.search(r'Jail list:\s*(.*)', after_status)
    stable = sets == after_sets and rules == after_rules and match is not None and after_names is not None and match[1] == after_names[1]
    return {'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'coverage_version':4,
            'measurement_stable':stable,
            'reader_revision':READER_REVISION,
            'active_jails':len(jails), 'daemon_ban_entries':sum(map(len,sets)),
            'daemon_unique_ips':len(reported), 'firewall_unique_ips':len(protected),
            'missing_f2b_rules':len(reported-protected),
            'orphan_firewall_ips':len(protected-reported),
            'duplicate_prefix_jails':sum(j.startswith('amsfb-amsfb-') for j in jails),
            'missing_jail_tickets':sum(len(s['missing_ips']) for s in details),
            'jails_without_actions':[s['jail'] for s in details if s['no_actions']],
            'jails_unverified':[s['jail'] for s in details if s['unsupported_actions']],
            'jail_coverage':details,
            'scope':'Reachable f2b IPv4/IPv6 source rules; does not attest end-to-end packet routing or other firewalls.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--monitor-hours', type=float, default=0)
    parser.add_argument('--interval', type=int, default=300)
    parser.add_argument('--deadline', type=float, help='Absolute UTC epoch; preserve an existing monitor end time')
    args = parser.parse_args()
    if not 0 <= args.monitor_hours <= 168 or not 30 <= args.interval <= 3600:
        parser.error('Monitoring must be bounded to 168h, intervals 30..3600s')
    if args.deadline is not None and (args.monitor_hours != 0 or not 0 < args.deadline <= time.time()+168*3600):
        parser.error('Invalid absolute deadline or incompatible monitor window')
    duration=max(0,args.deadline-time.time()) if args.deadline is not None else args.monitor_hours*3600
    deadline = time.monotonic() + duration
    while True:
        try:
            result = snapshot()
        except Exception as exc:
            result = {'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'error':type(exc).__name__}
            if isinstance(exc, AuditFailure):
                result.update(stage=exc.stage, jail=exc.jail, error=exc.kind, detail=exc.detail)
            else:
                result.update(stage='snapshot', jail=None, detail=re.sub(r'[\r\n\x00-\x1f]', ' ', str(exc))[:240])
        print(json.dumps(result), flush=True)
        if args.monitor_hours == 0 and args.deadline is None:
            return int(bool(result.get('error') or result.get('missing_f2b_rules') or result.get('missing_jail_tickets') or result.get('jails_without_actions') or result.get('jails_unverified')))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(json.dumps({'monitor_complete':True,
                'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat()}),flush=True)
            return 0
        time.sleep(min(args.interval, remaining))


if __name__ == '__main__':
    raise SystemExit(main())
