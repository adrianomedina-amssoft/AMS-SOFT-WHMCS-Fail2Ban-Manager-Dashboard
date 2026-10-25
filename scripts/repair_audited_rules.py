#!/usr/bin/python3
"""Root-only, explicit repair of the four audited legacy detections."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile

if os.geteuid()!=0 or int(os.environ.get('SUDO_UID',os.getuid()))!=0:
    raise SystemExit('Root CLI required')
parser=argparse.ArgumentParser()
parser.add_argument('--apply',action='store_true')
parser.add_argument('--jail',choices=['amsfb-wp-exploit-probe'])
args=parser.parse_args()
base=Path(__file__).resolve().parents[1]
h=runpy.run_path(str(base/'setup/amsfb-admin'))
targets=('amsfb-apache-probe','amsfb-ssl-probe','amsfb-apache-curl-probe','amsfb-apache-scanner')
if args.jail:targets=(args.jail,)
config=h['effective_config']()
audit_helper=dict(h,effective_config=lambda:{j:c for j,c in config.items() if j in targets})
audit=runpy.run_path(str(base/'scripts/native_filter_audit.py'))['audit'](audit_helper)
reports={row['jail']:row for row in audit}
for jail in targets:
    row=reports[jail]
    state=h['loaded_filter_state'](jail)
    proofs=[];patterns=[];refused=[]
    for pattern,branch in zip(state['patterns'],row['patterns']):
        if jail=='amsfb-wp-exploit-probe':
            old=r'^.* \[client <HOST>:\d+\]'
            anchored=r'^\[\s*\]\s+\[[^\]\r\n]+\]\s+(?:\[pid [^\]\r\n]+\]\s+)?\[client <HOST>:\d+\]'
            if pattern.startswith(old):pattern=anchored+pattern[len(old):]
        evidence=branch['positives']
        body='[Definition]\nfailregex = '+pattern.replace('%','%%')+'\nignoreregex =\n'
        try:
            h['validate_filter'](body,evidence)
            patterns.append(pattern);proofs.extend(evidence)
        except ValueError as error:
            refused.append({'branch':branch['index'],'code':getattr(error,'code','validation_error')})
    text='[Definition]\nfailregex = '+'\n            '.join(p.replace('%','%%') for p in patterns)+'\nignoreregex =\n'
    result={'jail':jail,'kept':len(patterns),'rejected':refused,'quarantine':not patterns,'expected':row['sha256'],'applied':False}
    if args.apply:
        result['native']=h['replace_existing_filter'](row['filter'],text,row['sha256'],list(dict.fromkeys(proofs)),quarantine=not patterns)
        result['applied']=True
    print(json.dumps(result),flush=True)
