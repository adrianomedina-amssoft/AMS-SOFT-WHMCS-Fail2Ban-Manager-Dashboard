"""Read-only HEAD checks against local Apache, with no authentication/cookies."""
import argparse
import json
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--https-host', required=True, help='Existing HTTPS vhost, resolved only to 127.0.0.1')
parser.add_argument('--http-prefix', default='/whmcs/modules/addons/amssoft_fail2ban')
parser.add_argument('--https-prefix', default='/modules/addons/amssoft_fail2ban')
args = parser.parse_args()
if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', args.https_host):
    parser.error('Invalid HTTPS host')
protected = ['.claude/settings.local.json', '.git/HEAD', 'setup/amsfb-admin', 'scripts/audit.py', 'tests/regression.php',
             'sql/install.sql', 'docs/PRD-code-review-20261012.md', 'data/.htaccess',
             'lib/Router.php', 'controllers/AIController.php', 'templates/layout.tpl', '.htaccess', 'CLAUDE.md']
results = []
for scheme, host, prefix in [('http', '127.0.0.1', args.http_prefix), ('https', args.https_host, args.https_prefix)]:
    for path, expected in [(p,403) for p in protected] + [('assets/css/amssoft_fail2ban.css',200)]:
        command = ['curl', '--noproxy', '*', '--silent', '--show-error', '--head', '--max-time', '10',
                   '--output', '/dev/null', '--write-out', '%{http_code}']
        if scheme == 'https':
            # Test access control on loopback; TLS certificate validation is a
            # separate concern. --resolve supplies the vhost's real SNI/Host.
            command += ['--insecure', '--resolve', f'{host}:443:127.0.0.1']
        command += [f'{scheme}://{host}{prefix.rstrip("/")}/{path}']
        response = subprocess.run(command, capture_output=True, text=True, timeout=15)
        result = {'scheme':scheme, 'path':path, 'status':response.stdout, 'expected':expected}
        results.append(result)
        if response.returncode or response.stdout != str(expected):
            raise RuntimeError('Access control failed: '+json.dumps(result))
print(f'PASS: {len(results)} local HTTP/HTTPS access checks; protected files 403, public CSS 200')
