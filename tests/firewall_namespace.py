"""Run only with: unshare --net python3 tests/firewall_namespace.py"""
import hashlib
import os
from pathlib import Path
import runpy
import shutil
import socket
import subprocess
import tempfile
import time

if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('Refusing to modify the host network namespace')


def run(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=30)


with tempfile.TemporaryDirectory(prefix='amsfb-firewall-test-') as d:
    root = Path(d)
    sock = str(root / 'fail2ban.sock')
    jail = 'amsfb-apache-php-webshell-scanner-long-name'
    action = 'amsfb-' + hashlib.sha256(jail.encode()).hexdigest()[:16]
    chain = 'f2b-' + action
    (root / 'filter.d').mkdir()
    (root / 'jail.d').mkdir()
    shutil.copytree('/etc/fail2ban/action.d', root / 'action.d')
    (root / 'probe.log').touch()
    (root / 'filter.d/probe.conf').write_text('[Definition]\nfailregex = ^TEST failed from <HOST>$\nignoreregex =\n')
    (root / 'fail2ban.conf').write_text('[Definition]\nloglevel = ERROR\nlogtarget = ' + str(root / 'server.log') + '\nsyslogsocket = auto\nsocket = ' + sock + '\npidfile = ' + str(root / 'server.pid') + '\ndbfile = ' + str(root / 'fail2ban.sqlite3') + '\n')
    (root / 'jail.conf').write_text('[DEFAULT]\nbackend = polling\nusedns = no\n[system-test]\nenabled = false\n[' + jail + ']\nenabled = true\nfilter = probe\nlogpath = ' + str(root / 'probe.log') + '\nmaxretry = 1\nfindtime = 600\nbantime = 300\naction = iptables-multiport[name=' + action + ',port="0:65535"]\n')
    client = ['/usr/bin/fail2ban-client', '-c', d, '-s', sock, '-p', str(root / 'server.pid')]
    started = False
    listener = None
    listener6 = None
    try:
        run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
        for ip in ['198.51.100.10/32','198.51.100.246/32']:
            run(['/usr/sbin/ip', 'address', 'add', ip, 'dev', 'lo'])
        run(client + ['start'])
        started = True
        listener = socket.socket()
        listener.bind(('198.51.100.10',55123))
        listener.listen(10)
        def connect():
            with socket.socket() as peer:
                peer.settimeout(1)
                peer.bind(('198.51.100.246',0))
                peer.connect(('198.51.100.10',55123))
        connect()
        run(client + ['set',jail,'banip','198.51.100.246'])
        helper = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'setup/amsfb-admin'))
        def isolated(args):
            if args[0] == '/usr/bin/fail2ban-client':
                args = [args[0],'-c',d,'-s',sock] + args[1:]
            return run(args)
        helper['check_ban'].__globals__['run'] = isolated
        for _ in range(50):
            if helper['check_ban'](jail,'198.51.100.246')['applied']:
                break
            time.sleep(.1)
        else:
            raise AssertionError('Firewall action not applied: ' + run(['/usr/sbin/iptables-save'])
                                 + '\nACTION: ' + run(client + ['get', jail, 'actions'])
                                 + '\nSERVER: ' + (root / 'server.log').read_text())
        assert len(chain) < 29
        assert chain in run(['/usr/sbin/iptables-save'])
        try:
            connect()
            raise AssertionError('Banned TCP connection unexpectedly succeeded')
        except (ConnectionRefusedError, TimeoutError):
            pass
        run(client + ['set',jail,'unbanip','198.51.100.246'])
        for _ in range(50):
            if not helper['check_ban'](jail,'198.51.100.246')['applied']:
                break
            time.sleep(.1)
        else:
            raise AssertionError('Firewall unban not applied')
        connect()
        for address in ['2001:db8::10/128','2001:db8::246/128']:
            run(['/usr/sbin/ip','-6','address','add',address,'dev','lo'])
        listener6=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        listener6.bind(('2001:db8::10',55123));listener6.listen(10)
        def connect6():
            with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as peer:
                peer.settimeout(1);peer.bind(('2001:db8::246',0));peer.connect(('2001:db8::10',55123))
        connect6();run(client+['set',jail,'banip','2001:db8::246'])
        for _ in range(50):
            if helper['check_ban'](jail,'2001:db8::246')['applied']:break
            time.sleep(.1)
        else:raise AssertionError('IPv6 firewall ban not confirmed')
        try:
            connect6();raise AssertionError('Banned IPv6 TCP connection succeeded')
        except (ConnectionRefusedError,TimeoutError):pass
        run(client+['set',jail,'unbanip','2001:db8::246'])
        for _ in range(50):
            if not helper['check_ban'](jail,'2001:db8::246')['applied']:break
            time.sleep(.1)
        else:raise AssertionError('IPv6 firewall unban not confirmed')
        connect6()
        # Reproduce production: an active ai-bans jail accepts tickets but has
        # no loaded action. Recovery must not extend the existing ticket.
        (root / 'jail.d/ai-test.local').write_text('[ai-bans]\nenabled = true\nfilter = probe\nlogpath = '+str(root / 'probe.log')+'\nmaxretry = 1\nbantime = 300\naction =\n')
        run(client+['reload'])
        run(client+['set','ai-bans','banip','198.51.100.246'])
        assert 'No actions' in run(client+['get','ai-bans','actions'])
        before=run(client+['get','ai-bans','banip','--with-time']).strip()
        def native_isolated(args):
            from fail2ban.client.csocket import CSocket
            connection=CSocket(sock,timeout=20)
            try:
                code,result=connection.send(args)
                if code:raise ValueError(str(result))
                return result
            finally:connection.close()
        helper['ensure_ai_jail'].__globals__.update(ROOT=root,BACKUPS=root/'backups',native_command=native_isolated)
        result=helper['ensure_ai_jail']('300')
        assert result['success'] and result['action_loaded'], result
        assert run(client+['get','ai-bans','banip','--with-time']).strip()==before, 'Ticket lifetime changed'
        assert helper['check_ban']('ai-bans','198.51.100.246')['applied']
        try:
            connect();raise AssertionError('Recovered AI jail did not reject TCP')
        except (ConnectionRefusedError,TimeoutError):pass
        assert helper['ensure_ai_jail']('300')['success'], 'Repeated recovery not idempotent'
        assert run(client+['get','ai-bans','banip','--with-time']).strip()==before
        run(client+['set','ai-bans','unbanip','198.51.100.246'])
        assert not helper['check_ban']('ai-bans','198.51.100.246')['applied'], 'Recovered action did not unban'
        connect()
        # An expired ticket must not reappear after a later recovery.
        run(client+['set','ai-bans','bantime','1'])
        run(client+['set','ai-bans','banip','198.51.100.246'])
        time.sleep(2)
        run(client+['set','ai-bans','bantime','300'])
        assert not helper['tickets'](['ai-bans'],native=True), 'Short ticket not expired'
        assert helper['ensure_ai_jail']('300')['success']
        assert not helper['tickets'](['ai-bans'],native=True), 'Expired ticket restored'
        # Reapply only an IPv6 ticket when the action is dropped, preserving
        # its exact identity and all native jails.
        run(client+['set','ai-bans','banip','2001:db8::246'])
        before6=run(client+['get','ai-bans','banip','--with-time']).strip()
        run(client+['set','ai-bans','delaction','iptables-multiport-amsfb-ai-bans'])
        assert helper['ensure_ai_jail']('300')['success']
        assert run(client+['get','ai-bans','banip','--with-time']).strip()==before6
        assert helper['check_ban']('ai-bans','2001:db8::246')['applied']
        try:
            connect6();raise AssertionError('Recovered IPv6 ticket did not reject TCP')
        except (ConnectionRefusedError,TimeoutError):pass
        run(client+['set','ai-bans','unbanip','2001:db8::246'])
        assert not helper['check_ban']('ai-bans','2001:db8::246')['applied'], run(['/usr/sbin/ip6tables-save'])
        connect6()
        # Native filter replacement/quarantine preserves both families and
        # exact lifetime; only the detection changes, never BanManager banip.
        managed=root/'filter.d/amsfb-repair.conf'
        managed.write_text('[Definition]\nfailregex = ^TEST failed from <HOST>$\nignoreregex =\n')
        (root/'jail.d/repair.local').write_text('[repair-test]\nenabled = true\nfilter = amsfb-repair\nlogpath = '+str(root/'probe.log')+'\nmaxretry = 3\nbantime = 300\naction = iptables-multiport[name=repair-test,port="0:65535"]\n')
        run(client+['reload'])
        for ip in ('198.51.100.246','2001:db8::246'):run(client+['set','repair-test','banip',ip])
        initial=run(client+['get','repair-test','banip','--with-time']).strip()
        candidate=(Path(__file__).resolve().parents[1]/'setup/fail2ban/filter.d/amsfb-apache-git-scanner.conf').read_text()
        proof=time.strftime('198.51.100.246 - - [%d/%b/%Y:%H:%M:%S %z]')+' "GET /.git/HEAD HTTP/1.1" 403 100 "-" "Mozilla/5.0"'
        repaired=helper['replace_existing_filter']('amsfb-repair',candidate,hashlib.sha256(managed.read_bytes()).hexdigest(),[proof])
        assert repaired['success'] and repaired['tickets_checked']==2,repaired
        assert run(client+['get','repair-test','banip','--with-time']).strip()==initial
        assert helper['check_ban']('repair-test','198.51.100.246')['applied']
        assert helper['check_ban']('repair-test','2001:db8::246')['applied']
        quarantined=helper['replace_existing_filter']('amsfb-repair','',hashlib.sha256(managed.read_bytes()).hexdigest(),[],quarantine=True)
        assert quarantined['success'] and quarantined['quarantined']
        assert run(client+['get','repair-test','banip','--with-time']).strip()==initial
        assert helper['check_ban']('repair-test','198.51.100.246')['applied']
        assert helper['check_ban']('repair-test','2001:db8::246')['applied']
        coverage=helper['ban_coverage']()
        protected={entry['ip'] for entry in coverage['entries'] if entry['jail']=='repair-test' and entry['ports']==[80,443]}
        assert protected=={'198.51.100.246','2001:db8::246'}, coverage
        assert run(client+['get','repair-test','banip','--with-time']).strip()==initial, 'Observation changed ticket'
        for ip in ('198.51.100.246','2001:db8::246'):run(client+['set','repair-test','unbanip',ip])
        assert not helper['check_ban']('repair-test','198.51.100.246')['applied']
        assert not helper['check_ban']('repair-test','2001:db8::246')['applied']
        assert not [entry for entry in helper['ban_coverage']()['entries'] if entry['jail']=='repair-test'], 'Removed tickets still considered protected'
        # Extend an existing managed rule to a second log without creating
        # another jail or changing either family's current tickets.
        learning=root/'filter.d/amsfb-learning.conf'
        first_log=root/'access_one.log';second_log=root/'access_two.log'
        first_log.touch();second_log.touch()
        old_pattern=r'^<HOST> - \S+ \[\s*\] "GET /\.git/HEAD HTTP/1\.1" 403 \S+'
        new_pattern=r'^<HOST> - \S+ \[\s*\] "GET /\.git/config HTTP/1\.1" 403 \S+'
        learning.write_text('[Definition]\nfailregex = '+old_pattern+'\nignoreregex =\n')
        (root/'jail.d/learning.local').write_text('[amsfb-learning]\nenabled = true\nfilter = amsfb-learning\nlogpath = '+str(first_log)+'\nmaxretry = 3\nbantime = 300\naction = iptables-multiport[name=amsfb-learning,port="0:65535"]\n')
        run(client+['reload'])
        for ip in ('198.51.100.246','2001:db8::246'):run(client+['set','amsfb-learning','banip',ip])
        initial_learning=run(client+['get','amsfb-learning','banip','--with-time']).strip()
        helper['extend_managed_rule'].__globals__['APPROVED_SOURCES']={str(first_log),str(second_log)}
        proof2=proof.replace('/.git/HEAD','/.git/config')
        manifest={'jail':'amsfb-learning','filter':'amsfb-learning','sha256':hashlib.sha256(learning.read_bytes()).hexdigest(),'patterns':[old_pattern,new_pattern],'sources':[str(first_log),str(second_log)],'evidence':[proof,proof2]}
        extended=helper['extend_managed_rule'](manifest)
        assert extended['success'] and extended['tickets_checked']==2,extended
        assert run(client+['get','amsfb-learning','banip','--with-time']).strip()==initial_learning
        assert helper['check_ban']('amsfb-learning','198.51.100.246')['applied']
        assert helper['check_ban']('amsfb-learning','2001:db8::246')['applied']
        assert helper['filter_coverage']('amsfb-learning',[proof2])['covered']==1
        before_failure=learning.read_bytes()
        manifest['sha256']=hashlib.sha256(before_failure).hexdigest()
        manifest['patterns']=[new_pattern]
        try:
            helper['extend_managed_rule'](manifest)
            raise AssertionError('Extension removed a previous expression')
        except ValueError:pass
        assert learning.read_bytes()==before_failure
        before_override=(root/'jail.d/zz-amsfb-managed-sources.local').read_bytes()
        manifest['patterns']=[old_pattern,new_pattern,new_pattern.replace('/config','/index')]
        manifest['evidence']=[proof,proof2,proof2.replace('/config','/index')]
        original_runner=helper['extend_managed_rule'].__globals__['run'];failed=[False]
        def injected_failure(args):
            if args[:2]==['/usr/bin/fail2ban-client','-t'] and not failed[0]:
                failed[0]=True
                raise RuntimeError('Injected configuration failure')
            return original_runner(args)
        helper['extend_managed_rule'].__globals__['run']=injected_failure
        try:
            try:helper['extend_managed_rule'](manifest);raise AssertionError('Injected failure not raised')
            except RuntimeError as error:assert str(error)=='Injected configuration failure'
        finally:helper['extend_managed_rule'].__globals__['run']=original_runner
        assert learning.read_bytes()==before_failure
        assert (root/'jail.d/zz-amsfb-managed-sources.local').read_bytes()==before_override
        assert run(client+['get','amsfb-learning','banip','--with-time']).strip()==initial_learning
        assert helper['check_ban']('amsfb-learning','198.51.100.246')['applied']
        # Reuse the fixed canonical jail, not a duplicate. Every path here is
        # a fixture; the host namespace and production logs are untouched.
        for ip in ('198.51.100.246','2001:db8::246'):run(client+['set','amsfb-learning','unbanip',ip])
        sources=[root/'access_default.log',root/'access_whmcs.log',root/'access_gateway.log']
        for p in sources:p.touch()
        canonical=root/'filter.d/apache-sensitive.conf'
        canonical.write_text('[Definition]\nfailregex = ^TEST failed from <HOST>$\nignoreregex =\n')
        (root/'jail.d/sensitive.local').write_text('[apache-sensitive]\nenabled = true\nfilter = apache-sensitive\nlogpath = '+str(sources[0])+'\nmaxretry = 3\nbantime = 300\nignoreip = 198.51.100.245\naction = iptables-multiport[name=apache-sensitive,port="0:65535"]\n')
        errors=[root/'error_default.log',root/'error_whmcs.log',root/'error_gateway.log']
        for p in errors:p.touch()
        for jail,log in [('apache-traversal',errors[0]),('apache-scan',sources[0])]:
            (root/('filter.d/'+jail+'.conf')).write_text('[Definition]\nfailregex = ^TEST failed from <HOST>$\nignoreregex =\n')
            (root/('jail.d/'+jail+'.local')).write_text('['+jail+']\nenabled = true\nfilter = '+jail+'\nlogpath = '+str(log)+'\nmaxretry = 1\nfindtime = 60\nbantime = 300\nignoreip = 198.51.100.245\naction = iptables-multiport[name='+jail+',port="0:65535"]\n')
        run(client+['reload'])
        helper['sync_sensitive_probes'].__globals__['SENSITIVE_SOURCES']=tuple(map(str,sources))
        helper['sync_sensitive_probes'].__globals__['TRAVERSAL_SOURCES']=tuple(map(str,errors))
        payload=dict(enabled=1,groups=list(helper['PROBE_GROUPS']),maxretry=1,findtime=60,bantime=300,whitelist=['198.51.100.245'])
        for ip in ('198.51.100.246','2001:db8::246'):run(client+['set','apache-sensitive','banip',ip])
        tickets_before=run(client+['get','apache-sensitive','banip','--with-time']).strip()
        assert helper['sync_sensitive_probes'](payload)['success']
        assert run(client+['get','apache-sensitive','banip','--with-time']).strip()==tickets_before
        assert helper['sync_sensitive_probes'](payload)['changed'] is False
        for ip in ('198.51.100.246','2001:db8::246'):run(client+['set','apache-sensitive','unbanip',ip])
        connect();connect6()
        for p,ip,target in [(sources[0],'198.51.100.246','/.git/config'),(sources[1],'2001:db8::246','/.env.secret'),(sources[2],'198.51.100.245','/wp-config.php')]:
            with p.open('a') as stream:stream.write(time.strftime(ip+' - - [%d/%b/%Y:%H:%M:%S %z]')+' "GET '+target+' HTTP/1.1" 200 100 "-" "fixture"\n')
        for _ in range(80):
            if all(helper['check_ban']('apache-sensitive',ip)['applied'] for ip in ('198.51.100.246','2001:db8::246')):break
            time.sleep(.1)
        else:raise AssertionError('One-hit IPv4/IPv6 native detector failed')
        assert not helper['check_ban']('apache-sensitive','198.51.100.245')['applied'],'Whitelist lost precedence'
        for attempt in (connect,connect6):
            try:attempt();raise AssertionError('One-hit ban did not block TCP')
            except (ConnectionRefusedError,TimeoutError):pass
        tickets_after=run(client+['get','apache-sensitive','banip','--with-time']).strip()
        assert helper['sync_sensitive_probes'](dict(payload,enabled=0))['success']
        assert run(client+['get','apache-sensitive','banip','--with-time']).strip()==tickets_after,'Disable renewed/removed ban'
        prior_filter=canonical.read_bytes();prior_override=(root/'jail.d/zzzz-amsfb-sensitive.local').read_bytes()
        original_runner=helper['sync_sensitive_probes'].__globals__['run'];failed=[False]
        def fail_sensitive_config(args):
            if args[:2]==['/usr/bin/fail2ban-client','-t'] and not failed[0]:
                failed[0]=True;raise RuntimeError('Injected sensitive config failure')
            return original_runner(args)
        helper['sync_sensitive_probes'].__globals__['run']=fail_sensitive_config
        try:
            try:helper['sync_sensitive_probes'](payload);raise AssertionError('Sensitive failure not injected')
            except RuntimeError as error:assert str(error)=='Injected sensitive config failure'
        finally:helper['sync_sensitive_probes'].__globals__['run']=original_runner
        assert canonical.read_bytes()==prior_filter and (root/'jail.d/zzzz-amsfb-sensitive.local').read_bytes()==prior_override
        assert run(client+['get','apache-sensitive','banip','--with-time']).strip()==tickets_after
        # Traverse error logs on the companion jail, one real event per family.
        for ip in ('198.51.100.246','2001:db8::246'):run(client+['set','apache-sensitive','unbanip',ip])
        assert helper['sync_sensitive_probes'](payload)['success']
        for p,ip in [(errors[1],'198.51.100.246'),(errors[2],'2001:db8::246')]:
            with p.open('a') as stream:stream.write(time.strftime('[%a %b %d %H:%M:%S %Y]')+' [core:error] [pid 123] [client '+ip+':54321] AH10244: invalid URI path (/icons/.%%32%65/.%%32%65/apache2/icons/probe.png)\n')
        for _ in range(80):
            if all(helper['check_ban']('apache-traversal',ip)['applied'] for ip in ('198.51.100.246','2001:db8::246')):break
            time.sleep(.1)
        else:raise AssertionError('One-hit encoded traversal failed in error log')
        assert helper['loaded_filter_state']('apache-scan')['patterns']==[r'^(?!)<HOST>$']
        for attempt in (connect,connect6):
            try:attempt();raise AssertionError('Traversal ban did not block TCP')
            except (ConnectionRefusedError,TimeoutError):pass
        # Query traversal: first request, current timestamp, isolated IPv4/IPv6 only.
        for ip in ('198.51.100.246','2001:db8::246'):run(client+['set','apache-traversal','unbanip',ip])
        for p,ip in [(sources[1],'198.51.100.246'),(sources[2],'2001:db8::246')]:
            with p.open('a') as stream:stream.write(ip+' - - ['+time.strftime('%d/%b/%Y:%H:%M:%S %z')+'] "GET /retired-page?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1" 200 10 "-" "fixture"\n')
        for _ in range(80):
            if all(helper['check_ban']('apache-sensitive',ip)['applied'] for ip in ('198.51.100.246','2001:db8::246')):break
            time.sleep(.1)
        else:raise AssertionError('One-hit query traversal failed')
        for attempt in (connect,connect6):
            try:attempt();raise AssertionError('Query traversal ban did not block TCP')
            except (ConnectionRefusedError,TimeoutError):pass
        print('PASS: query traversal natively banned IPv4/IPv6 on first request and blocked TCP')
        print('PASS: encoded AH10244 natively banned IPv4/IPv6 from error logs; broad status detector disabled with actions preserved')
        print('PASS: one request natively banned IPv4/IPv6 and blocked TCP; whitelist, idempotence, disable and rollback preserved tickets')
        print('PASS: managed multi-log extension preserved IPv4/IPv6 tickets and coverage; branch removal refused')
        print('PASS: failed managed extension restored filter, logpaths and unchanged active tickets')
        print('PASS: read-only HTTP coverage confirmed IPv4/IPv6 and removed protection after unban; tickets unchanged')
        print('PASS: targeted native filter replacement and detection-only quarantine preserved IPv4/IPv6 tickets, actions and unban')
        print('PASS: isolated IPv4/IPv6 TCP ban/unban; actionless AI jail recovered with unchanged ticket lifetime and idempotence; no host firewall changes')
    finally:
        if listener is not None:
            listener.close()
        if listener6 is not None:
            listener6.close()
        if started:
            run(client + ['stop'])
