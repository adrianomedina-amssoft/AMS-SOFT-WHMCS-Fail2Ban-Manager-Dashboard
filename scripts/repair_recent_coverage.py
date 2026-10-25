#!/usr/bin/python3
"""Root-only audited detector repair; never bans IPs or reactivates quarantines."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import time
from urllib.parse import unquote

# Private deployment IDs are deliberately not distributed.
AUDITED_IDS = []

def classify_path(path):
    decoded=unquote(path.split('?',1)[0]).lower()
    if re.search(r'(?:^|/)\.env(?:$|[./])',decoded):return 'amsfb-apache-env-probe'
    if re.search(r'(?:^|/)\.(?:git|svn)/(?:head|config|wc\.db|entries)$',decoded):return 'amsfb-apache-git-probe'
    if decoded in ('/administrator/manifests/files/joomla.xml','/magento_version','/core/install.php'):return 'amsfb-apache-cms-probe'
    return None

def literal_pattern(paths):
    # Every literal alternative is derived from an individually checked sample.
    paths=sorted(set(paths))
    return r'^<HOST> - \S+ \[\s*\] "(?:GET|HEAD) (?:'+ '|'.join(re.escape(p) for p in paths)+r')(?:\?[^ "\r\n]*)? HTTP/\d\.\d" (?:403|404) \S+'

def php(code):
    bootstrap="""require '/var/www/html/whmcs/configuration.php';require '/var/www/html/whmcs/vendor/autoload.php';require '/var/www/html/whmcs/modules/addons/amssoft_fail2ban/lib/Router.php';$c=new WHMCS\\Database\\Capsule;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();"""
    return json.loads(subprocess.check_output(['/usr/bin/php','-r',bootstrap+code],text=True))

def prepare(helper, base):
    if not AUDITED_IDS:
        raise ValueError('No deployment-specific audited IDs configured; no operation performed')
    ids=','.join(str(i) for i in AUDITED_IDS)
    rows=php("$db=WHMCS\\Database\\Capsule::connection();$db->statement('SET TRANSACTION READ ONLY');$db->beginTransaction();try{echo json_encode(WHMCS\\Database\\Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->whereIn('id',["+ids+"])->where('classification','ban')->where('status','!=','rejected')->where('confidence','>=',90)->get(['id','ip','source_log','evidence','failregex']));}finally{$db->rollBack();}")
    cfg=helper['effective_config']()
    names=['amsfb-apache-env-probe','amsfb-apache-git-probe','amsfb-apache-cms-probe']
    native=helper['native_command']
    def audit_command(args):
        result=native(args)
        if len(args)==3 and args[0]=='get' and args[2]=='logpath':
            # Read-only positives from before midnight; never add rotations to
            # the jail logpath or change the age of decision evidence.
            return result+[str(p) for path in result for suffix in ('.1','.2.gz','.3.gz')
                           if (p:=Path(path+suffix)).is_file()]
        return result
    audit=runpy.run_path(str(base/'scripts/native_filter_audit.py'))['audit'](dict(helper,native_command=audit_command,effective_config=lambda:{j:c for j,c in cfg.items() if j in names}))
    audited={r['jail']:r for r in audit};groups={}
    for row in rows:
        if Path(row['source_log']).name.startswith('access') is False:continue
        evidence=json.loads(row['evidence'] or '[]')
        try:helper['normalize_evidence_filter']({'patterns':row['failregex'].splitlines(),'evidence':evidence})
        except ValueError:continue
        for line in evidence:
            if helper['source_peer'](line)!=row['ip']:continue
            m=re.search(r'"(GET|HEAD) ([^ ]+) HTTP/[^"]+" (403|404)',line)
            if not m:continue
            path=m[2].split('?',1)[0];jail=classify_path(path)
            if jail is None:continue
            group=groups.setdefault(jail,{'paths':[],'sources':[],'evidence':[],'ids':[]})
            group['paths'].append(path);group['sources'].append(row['source_log']);group['evidence'].append(line);group['ids'].append(row['id'])
    entries=[]
    for jail,group in groups.items():
        item={'jail':jail,'ids':sorted(set(group['ids'])),'status':'deferred'}
        if jail not in audited:item['reason']='active_rule_unavailable';entries.append(item);continue
        report=audited[jail];state=helper['loaded_filter_state'](jail)
        if state['prefregex'] or state['ignoreregex'] or any('(?!)' in p for p in state['patterns']):
            item['reason']='quarantined_or_contextual';entries.append(item);continue
        proof=list(dict.fromkeys(group['evidence']+[line for branch in report['patterns'] for line in branch['positives']]))
        pattern=literal_pattern(group['paths']);patterns=list(dict.fromkeys(state['patterns']+[pattern]))
        text='[Definition]\nfailregex = '+'\n            '.join(p.replace('%','%%') for p in patterns)+'\nignoreregex =\n'
        try:helper['validate_filter'](text,proof)
        except ValueError as exc:item['reason']=getattr(exc,'code','validation_refused');entries.append(item);continue
        item.update(status='ready',sha256=report['sha256'],patterns=patterns,
            sources=sorted(set(state['paths']+group['sources'])),evidence=proof)
        entries.append(item)
    return {'created_at':int(time.time()),'entries':entries}

def apply_plan(manifest, helper):
    # SQL locks/caps remain in one living process while native commits execute.
    # PHP runner below owns these locks and invokes one helper at a time.
    raise RuntimeError('Use repair_recent_coverage.php for locked/quota-aware apply')

def main():
    if os.geteuid()!=0 or int(os.environ.get('SUDO_UID',os.getuid()))!=0:raise SystemExit('Root CLI required')
    parser=argparse.ArgumentParser();parser.add_argument('--plan',required=True)
    parser.add_argument('--jail',choices=['amsfb-apache-env-probe','amsfb-apache-git-probe','amsfb-apache-cms-probe'])
    args=parser.parse_args();destination=Path(args.plan)
    if not str(destination.resolve()).startswith('/var/backups/amssoft_fail2ban/') or destination.exists():raise SystemExit('New private backup artifact required')
    helper=runpy.run_path('/usr/local/sbin/amsfb-admin');base=Path(__file__).resolve().parents[1]
    manifest=prepare(helper,base)
    if args.jail:manifest['entries']=[r for r in manifest['entries'] if r['jail']==args.jail]
    destination.write_text(json.dumps(manifest));destination.chmod(0o600)
    print(json.dumps({'plan':str(destination),'entries':[{'jail':r['jail'],'status':r['status'],'reason':r.get('reason'),'decisions':len(r['ids'])} for r in manifest['entries']]}))
if __name__=='__main__':main()
