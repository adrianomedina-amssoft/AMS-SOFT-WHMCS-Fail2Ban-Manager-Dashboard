"""Shared, fail-closed observation of each jail's own INPUT coverage."""
import ipaddress
import re
import shlex
import socket
import threading

# libc service lookup may use shared storage even across independent requests.
_service_lock = threading.Lock()
READER_REVISION = 3


def service_port(value, protocol):
    if value.isdigit():
        return int(value)
    with _service_lock:
        return socket.getservbyname(value, protocol)


def ranges(value, protocol='tcp'):
    result = []
    for token in value.strip().split(','):
        token=token.strip()
        pair = token.split(':') if ':' in token else (token.split('-') if re.fullmatch(r'\d+-\d+',token) else [token])
        if len(pair) > 2 or any(not part for part in pair) or protocol not in ('tcp', 'udp'):
            raise ValueError('Invalid port range')
        lo = service_port(pair[0], protocol)
        hi = lo if len(pair) == 1 else service_port(pair[1], protocol)
        if not 0 <= lo <= hi <= 65535:
            raise ValueError('Invalid port range')
        result.append((lo, hi))
    return result


def action_specs(jail, command):
    output = command(['/usr/bin/fail2ban-client', 'get', jail, 'actions'])
    names = [s.strip() for s in output.splitlines()[1:]
             if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', s.strip())]
    specs = []
    for name in names:
        prefix = ['/usr/bin/fail2ban-client', 'get', jail, 'action', name]
        template = command(prefix + ['actionban'])
        match = re.search(r'(?:-I|-A)\s+(f2b-[A-Za-z0-9_-]+)\s', template)
        if not match:
            specs.append({'action': name, 'supported': False})
            continue
        protocol = command(prefix + ['protocol']).strip()
        ports = command(prefix + ['port']).strip()
        if protocol not in ('tcp', 'udp'):
            specs.append({'action': name, 'supported': False})
            continue
        specs.append({'action': name, 'supported': True, 'chain': match[1],
                      'protocol': protocol, 'ports': ports, 'ranges': ranges(ports, protocol)})
    return specs


def read_rules(command, version):
    binary = '/usr/sbin/ip6tables-save' if version == 6 else '/usr/sbin/iptables-save'
    return [shlex.split(s) for s in command([binary, '-t', 'filter']).splitlines() if s.startswith('-A ')]


def option(rule, flag, default=None):
    return rule[rule.index(flag)+1] if flag in rule else default


def covers(rules, spec, ip, network_reader=ipaddress.ip_network):
    """Only own, unconditional source rejects via INPUT; unknown matches fail closed."""
    address = ipaddress.ip_address(ip)
    chain = spec['chain']
    def may_match(r):
        # Destination/interface/state are unknown: they may match some traffic.
        # Negation and unfamiliar matches cannot prove a bypass irrelevant.
        if '!' in r:
            return True
        protocol = option(r, '-p')
        if protocol not in (None, 'all', spec['protocol']):
            return False
        source = option(r, '-s')
        if source and address not in network_reader(source):
            return False
        ports = option(r, '--dports', option(r, '--dport'))
        if ports and not any(a <= hi and lo <= b for a, b in ranges(ports, spec['protocol'])
                             for lo, hi in spec['ranges']):
            return False
        return True

    def bypass(r, returning=False, visited=frozenset()):
        if not may_match(r):
            return False
        # goto does not push a return address. RETURN (including implicit
        # end-of-chain) can skip the caller's remaining rules. Conservatively
        # refuse a potentially matching goto instead of treating it as jump.
        if '-g' in r:
            return True
        target = option(r, '-j')
        if target == 'ACCEPT' or target == 'RETURN' and returning:
            return True
        if target in (None, 'RETURN', 'DROP', 'REJECT', 'LOG', 'NFLOG', 'MARK', 'CONNMARK'):
            return False
        children = [item for item in rules if item[1] == target]
        if not children or target in visited:
            return True  # Unknown extension or traversal: cannot attest coverage.
        return any(bypass(item, visited=visited | {target}) for item in children)

    rejects = []
    for r in rules:
        if r[1] != chain:
            continue
        if bypass(r, returning=True):
            break
        if option(r, '-j') in ('DROP', 'REJECT') and '-s' in r and may_match(r):
            rejects.append(r)
    def simple_reject(r):
        allowed = {'-s', '-j', '--reject-with'}
        i = 2
        while i < len(r):
            if r[i] not in allowed or i+1 >= len(r):
                return False
            i += 2
        return True
    if not any(simple_reject(r) for r in rejects):
        return False
    reachable = []
    for r in rules:
        if r[1] != 'INPUT':
            continue
        if bypass(r, returning=True):
            break
        if option(r, '-j') != chain:
            continue
        # A restricted source/destination/interface/state cannot attest full coverage.
        allowed = {'-p', '-m', '--dports', '--dport', '-j'}
        if any(r[i] not in allowed for i in range(2, len(r), 2)):
            continue
        protocol = option(r, '-p')
        if protocol not in (None, 'all', spec['protocol']):
            continue
        ports = option(r, '--dports', option(r, '--dport'))
        reachable.extend(ranges(ports, spec['protocol']) if ports else [(0, 65535)])
    for lo, hi in spec['ranges']:
        cursor = lo
        for a, b in sorted(reachable):
            if b < cursor:
                continue
            if a > cursor:
                break
            cursor = max(cursor, b+1)
            if cursor > hi:
                break
        if cursor <= hi:
            return False
    return True


def inspect(jail, ips, command, rules=None):
    specs = action_specs(jail, command)
    missing = []
    rules = {} if rules is None else rules
    for ip in ips:
        version = ipaddress.ip_address(ip).version
        if version not in rules:
            rules[version] = read_rules(command, version)
        if not specs or any(not s['supported'] or not covers(rules[version], s, ip) for s in specs):
            missing.append(ip)
    return {'jail': jail, 'no_actions': not bool(specs),
            'unsupported_actions': [s['action'] for s in specs if not s['supported']],
            'actions': specs, 'tickets': len(ips), 'missing_ips': missing}
