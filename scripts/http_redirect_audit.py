#!/usr/bin/python3
"""Read-only check of enabled HTTP virtualhost logging against the loaded sensitive jail.

This deliberately supports simple literal virtualhost blocks, not arbitrary Apache
configuration evaluation. Conditional/nested/indirect logging is reported unknown.
No SQL, provider, repair, reload, ban or unban operation is available.
"""
import json
import os
from pathlib import Path
import re
import runpy
import shlex

APPROVED_LOGS = frozenset((
    '/var/log/apache2/access.log', '/var/log/apache2/access_whmcs.log',
    '/var/log/apache2/access_license_gateway.log',
))


def inspect_text(text, source='<fixture>'):
    if len(text.encode()) > 262144 or '\\\n' in text:
        return [{'source': source, 'status': 'unknown', 'reason': 'size_or_continuation'}]
    # Full-line comments cannot introduce a fake virtualhost. Directive arguments
    # are parsed with shlex below; quoted spaces and trailing comments are supported.
    text = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    blocks = list(re.finditer(r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost\s*>', text, re.I | re.S))
    if len(blocks) != len(re.findall(r'<VirtualHost\b', text, re.I)):
        return [{'source': source, 'status': 'unknown', 'reason': 'unbalanced_virtualhost'}]
    rows = []
    for match in blocks:
        addresses = match[1].split()
        if not any(address == '80' or address.endswith(':80') for address in addresses):
            continue
        directives = []
        reason = None
        for line in match[2].splitlines():
            try:
                args = shlex.split(line, comments=True)
            except ValueError:
                reason = 'directive_syntax'
                break
            if not args:
                continue
            key = args[0].lower()
            if key.startswith('<') or key in ('include', 'includeoptional', 'globallog', 'logformat'):
                reason = 'indirect_or_conditional_configuration'
                break
            directives.append((key, args[1:]))
        names = [args[0] for key, args in directives if key == 'servername' and len(args) == 1]
        aliases = [name for key, args in directives if key == 'serveralias' for name in args]
        logs = [args for key, args in directives if key == 'customlog']
        row = {'source': source, 'addresses': addresses, 'server': names[0] if names else '(default)',
               'aliases': aliases, 'status': 'unknown', 'reason': reason, 'log': None}
        if reason is None:
            if len(names) > 1 or len(logs) > 1:
                row['reason'] = 'ambiguous_directives'
            elif not logs:
                row['reason'] = 'explicit_http_log_missing'
            elif len(logs[0]) != 2:
                row['reason'] = 'conditional_or_unsupported_customlog'
            else:
                target, fmt = logs[0]
                target = target.replace('${APACHE_LOG_DIR}/', '/var/log/apache2/', 1)
                row['log'] = target
                if target not in APPROVED_LOGS:
                    row['reason'] = 'log_not_approved'
                elif fmt != 'combined':
                    row['reason'] = 'format_not_combined'
                else:
                    row.update(status='configured', reason='literal_combined_log')
        rows.append(row)
    return rows


def check_coverage(rows, loaded_paths):
    result = []
    for original in rows:
        row = dict(original)
        if row['status'] == 'configured':
            if row['log'] in loaded_paths:
                row.update(status='covered', reason='combined_log_monitored')
            else:
                row.update(status='unknown', reason='loaded_jail_source_missing')
        result.append(row)
    return result


def audit():
    if os.geteuid() != 0:
        raise PermissionError('Root CLI required')
    directory = Path('/etc/apache2/sites-enabled')
    files = sorted(directory.glob('*.conf'))
    if not files or len(files) > 64:
        raise ValueError('Enabled sites unavailable or over limit')
    rows = []
    for path in files:
        target = path.resolve(strict=True)
        if target.parent not in (directory, Path('/etc/apache2/sites-available')) or target.stat().st_uid != 0:
            raise ValueError('Unexpected enabled site target')
        if target.stat().st_size > 262144:
            raise ValueError('Site exceeds read limit')
        rows.extend(inspect_text(target.read_text(), str(path)))
    helper = runpy.run_path('/usr/local/sbin/amsfb-admin')
    native = helper['native_command']
    paths = native(['get', 'apache-sensitive', 'logpath'])
    maxretry = native(['get', 'apache-sensitive', 'maxretry'])
    rows = check_coverage(rows, paths)
    return {'success': bool(rows) and all(r['status'] == 'covered' for r in rows),
            'scope': 'Literal enabled port-80 virtualhosts and loaded apache-sensitive sources; smoke test required after reload',
            'virtualhosts': rows, 'sensitive_maxretry': maxretry, 'loaded_paths': paths,
            'read_only': True}


if __name__ == '__main__':
    try:
        report = audit()
    except Exception as exc:
        report = {'success': False, 'status': 'unknown', 'error_type': type(exc).__name__, 'read_only': True}
    print(json.dumps(report, ensure_ascii=False))
    raise SystemExit(0 if report['success'] else 3)
