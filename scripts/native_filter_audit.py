#!/usr/bin/python3
"""Read-only bounded capture audit of loaded native jail expressions."""
import collections
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import runpy
from fail2ban.server.failregex import FailRegex, Regex, RegexException
from fail2ban.server.datedetector import DateDetector


def audit(helper, limit=20000):
    native = helper['native_command']
    config = helper['effective_config']()
    detector = DateDetector()
    detector.addDefaultTemplate()
    report = []
    cached = {}
    for jail, settings in config.items():
        if settings.get('enabled', '').lower() not in ('true', '1', 'yes', 'on'):
            continue
        patterns = native(['get', jail, 'failregex'])
        paths = native(['get', jail, 'logpath'])
        expressions = []
        for pattern in patterns:
            try:
                expressions.append(FailRegex(pattern))
            except RegexException:
                # Some stock filters inherit peer from prefregex. Do not
                # misreport their body-only regex as an unsafe capture.
                expressions.append(None)
        rows = [{'index': i, 'regex': p, 'matches': 0, 'wrong_peer': 0, 'examples': [], 'positives': []}
                for i, p in enumerate(patterns)]
        pref = None
        bodies = {}
        if any(expression is None for expression in expressions):
            definition = native(['get', jail, 'prefregex'])
            if definition:
                pref = FailRegex(definition)
                bodies = {i: Regex(patterns[i]) for i, expression in enumerate(expressions) if expression is None}
        for path in paths:
            if path not in cached:
                opener = gzip.open if str(path).endswith('.gz') else open
                with opener(path, 'rt', errors='replace') as stream:
                    lines = collections.deque(stream, maxlen=limit)
                parsed = []
                for line in lines:
                    line = line.rstrip('\r\n')
                    if len(line) > 65536:
                        continue
                    peer = helper['source_peer'](line)
                    if peer is None:
                        continue
                    match = detector.matchTime(line)[0]
                    split = (line[:match.start(1)], line[match.start(1):match.end(1)], line[match.end(1):]) if match else (line, '', '')
                    parsed.append((line, peer, split))
                cached[path] = parsed
            for line, peer, split in cached[path]:
                for expression, row in zip(expressions, rows):
                    if expression is None:
                        row['contextual_prefregex'] = True
                        if pref is None:
                            row['unverified_prefregex'] = True
                            continue
                        row['prefregex_checked'] = True
                        pref.search([split])
                        if not pref.hasMatched():
                            continue
                        content = pref.getGroups().get('content', '')
                        body = bodies[row['index']]
                        body.search([(content, '', '')])
                        if not body.hasMatched():
                            continue
                        host = pref.getHost()
                    else:
                        expression.search([split])
                        if not expression.hasMatched():
                            continue
                        host = expression.getHost()
                    row['matches'] += 1
                    try:
                        exact = str(ipaddress.ip_address(host)) == peer
                    except ValueError:
                        exact = False
                    if not exact:
                        row['wrong_peer'] += 1
                        if len(row['examples']) < 3:
                            row['examples'].append({'peer': peer, 'captured': host, 'line': line})
                    elif len(row['positives']) < 5:
                        row['positives'].append(line)
        name = settings.get('filter', '').split('[', 1)[0]
        target = helper['ROOT'] / 'filter.d' / (name + '.conf')
        report.append({'jail': jail, 'filter': name, 'paths': paths, 'patterns': rows,
                       'sha256': hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None})
    return report


if __name__ == '__main__':
    helper = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'setup/amsfb-admin'))
    print(json.dumps(audit(helper), ensure_ascii=False))
