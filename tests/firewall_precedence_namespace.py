"""Independent TCP oracle for coverage; run with unshare --net python3 ... ."""
import argparse
import os
from pathlib import Path
import runpy
import shlex
import socket
import subprocess

if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('Refusing to modify the host network namespace')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--reader', default=str(Path(__file__).resolve().parents[1] / 'scripts/firewall_state.py'))
args = parser.parse_args()
covers = runpy.run_path(args.reader)['covers']
def run(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=10)
run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
checks = 0
for version, binary, target, source, other in [
    (4, '/usr/sbin/iptables', '198.51.100.10', '198.51.100.246', '203.0.113.7'),
    (6, '/usr/sbin/ip6tables', '2001:db8::10', '2001:db8::246', '2001:db8::7'),
]:
    family = socket.AF_INET6 if version == 6 else socket.AF_INET
    for ip in [target, source]:
        run(['/usr/sbin/ip', 'address', 'add', ip + ('/128' if version == 6 else '/32'), 'dev', 'lo'])
    for chain in ['f2b-meta', 'meta-skip']:
        run([binary, '-N', chain])
    listeners = []
    try:
        for port in [55123, 55124]:
            listener = socket.socket(family, socket.SOCK_STREAM)
            listener.bind((target, port)); listener.listen(10); listener.settimeout(1)
            listeners.append(listener)
        own = '-A INPUT -p tcp -j f2b-meta'
        reject = '-A f2b-meta -s ' + source + ' -j REJECT'
        cases = [
            ('normal reject', [own, reject], True, [False, False]),
            ('INPUT goto RETURN', ['-A INPUT -g meta-skip', own, '-A meta-skip -j RETURN', reject], False, [True, True]),
            ('own goto RETURN', [own, '-A f2b-meta -g meta-skip', reject, '-A meta-skip -j RETURN'], False, [True, True]),
            ('goto implicit return', ['-A INPUT -g meta-skip', own, '-A meta-skip -s ' + other + ' -j RETURN', reject], False, [True, True]),
            ('jump RETURN resumes INPUT', ['-A INPUT -j meta-skip', own, '-A meta-skip -j RETURN', reject], True, [False, False]),
            ('partial ACCEPT', ['-A INPUT -p tcp --dport 55123 -j ACCEPT', own, reject], False, [True, False]),
            ('own early RETURN', [own, '-A f2b-meta -j RETURN', reject], False, [True, True]),
            ('reject precedes RETURN', [own, reject, '-A f2b-meta -j RETURN'], True, [False, False]),
        ]
        for label, lines, expected, traffic in cases:
            for chain in ['INPUT', 'f2b-meta', 'meta-skip']:
                run([binary, '-F', chain])
            for line in lines:
                run([binary] + shlex.split(line))
            actual_traffic = []
            for port, listener in zip([55123, 55124], listeners):
                with socket.socket(family, socket.SOCK_STREAM) as peer:
                    peer.settimeout(.5); peer.bind((source, 0))
                    try:
                        peer.connect((target, port))
                    except (ConnectionRefusedError, TimeoutError):
                        actual_traffic.append(False)
                    else:
                        connection, _ = listener.accept(); connection.close()
                        actual_traffic.append(True)
            assert actual_traffic == traffic, (version, label, actual_traffic, traffic)
            # Use the kernel's serialized rules, not the setup fixture, as input.
            serialized = run([binary + '-save', '-t', 'filter'])
            rules = [shlex.split(line) for line in serialized.splitlines() if line.startswith('-A ')]
            observed = covers(rules, {'chain':'f2b-meta','protocol':'tcp','ranges':[(55123,55124)]}, source)
            assert observed == expected, (version, label, 'coverage', observed, 'expected', expected)
            checks += 1
    finally:
        for listener in listeners:
            listener.close()
print(f'PASS: {checks} IPv4/IPv6 precedence scenarios compared with real TCP; isolated namespace only')
