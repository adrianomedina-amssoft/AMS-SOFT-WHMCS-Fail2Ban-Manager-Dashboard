"""Pure, bounded migration for five pre-validator legacy filters.

No CLI, filesystem writes or new detector semantics. Deployment must compare
hashes, validate offline, lock, reload and verify tickets/actions separately.
"""
import configparser

NAMES = frozenset('amsfb-apache-'+name for name in
                  ('api-probe', 'badbots', 'cart-probe', 'cms-probe', 'whmcs-probe'))
ACCESS = r'^<HOST>(?= - \S+ \[\s*\] ")'
ERROR = r'^\[\s*\]\s+\[[^\]\r\n]+\]\s+(?:\[pid [^\]\r\n]+\]\s+)?\[client '


def repair(name, text):
    if name not in NAMES:
        raise ValueError('Outside finite legacy repair scope')
    cfg = configparser.RawConfigParser()
    cfg.read_string(text)
    if cfg.sections() != ['Definition'] or cfg.defaults() or set(cfg['Definition']) != {'failregex', 'ignoreregex'} or cfg.get('Definition', 'ignoreregex').strip():
        raise ValueError('Unexpected legacy context')
    patterns = []
    for pattern in cfg.get('Definition', 'failregex').splitlines():
        pattern = pattern.strip()
        if not pattern:
            continue
        if pattern.count('<HOST>') != 1:
            raise ValueError('Ambiguous legacy peer')
        if pattern.startswith(r'^.* \[client <HOST>'):
            pattern = ERROR + pattern[len(r'^.* \[client '):]
        elif pattern.startswith(r'^\[.*\] \[php:notice\] \[pid \d+:tid \d+\] \[client <HOST>'):
            pattern = pattern.replace(r'^\[.*\]', r'^\[\s*\]', 1)
        else:
            for prefix in ('^.* <HOST>', '^.*<HOST>', '^<HOST>'):
                if pattern.startswith(prefix):
                    suffix = pattern[len(prefix):]
                    pattern = ACCESS + suffix
                    break
            else:
                raise ValueError('Unexpected legacy header')
        patterns.append(pattern)
    if not patterns:
        raise ValueError('Empty legacy filter')
    return ('# AMSFB v2.2.55: bounded peer-header repair; detector predicates preserved.\n'
            '[Definition]\nfailregex = ' + '\n            '.join(patterns) + '\nignoreregex =\n')
