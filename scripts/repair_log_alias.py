#!/usr/bin/python3
"""Detach the fixed root mirror without replacing/truncating the active log."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile


def repair(active, alias, backup_dir, apply=False):
    active, alias, backup_dir = Path(active), Path(alias), Path(backup_dir)
    original=active.lstat()
    if not stat.S_ISREG(original.st_mode) or original.st_uid!=os.geteuid():
        raise ValueError('Active log is not an owned regular file')
    if alias.is_symlink():
        if alias.resolve()==active.resolve() and original.st_nlink==1:
            return {'changed':False,'already_repaired':True,'inode':original.st_ino}
        raise ValueError('Unexpected symbolic alias')
    mirror=alias.lstat()
    identity=lambda s:(s.st_dev,s.st_ino)
    if not stat.S_ISREG(mirror.st_mode) or identity(original)!=identity(mirror) or original.st_nlink!=2:
        raise ValueError('Targets are not the expected two-link log')
    if not apply:
        return {'changed':False,'dry_run':True,'inode':original.st_ino,'links':original.st_nlink,'size':original.st_size}
    if not backup_dir.is_dir() or backup_dir.is_symlink():
        raise ValueError('Unsafe backup directory')
    name=secrets.token_hex(8)
    backup=backup_dir/('error-whmcs-alias-'+name+'.bin')
    temporary=alias.parent/('.amsfb-error-alias-'+name)
    fd=os.open(active,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        if identity(os.fstat(fd))!=identity(original):
            raise ValueError('Active log changed before copy')
        remaining=original.st_size;digest=hashlib.sha256()
        with os.fdopen(fd,'rb',closefd=False) as source,open(backup,'xb') as target:
            os.chmod(backup,0o600)
            while remaining:
                block=source.read(min(1024*1024,remaining))
                if not block:raise ValueError('Log truncated during backup')
                target.write(block);digest.update(block);remaining-=len(block)
            target.flush();os.fsync(target.fileno())
        if hashlib.sha256(backup.read_bytes()).hexdigest()!=digest.hexdigest():
            raise ValueError('Backup verification failed')
        os.symlink(str(active),temporary)
        if identity(active.lstat())!=identity(original) or identity(alias.lstat())!=identity(original) or active.stat().st_nlink!=2:
            raise ValueError('Targets changed before replacement')
        os.replace(temporary,alias)
        after=active.lstat()
        if identity(after)!=identity(original) or after.st_nlink!=1 or alias.resolve()!=active.resolve():
            raise ValueError('Alias replacement not verified; inspect retained backup')
        return {'changed':True,'inode':after.st_ino,'links':after.st_nlink,'snapshot_bytes':original.st_size,'sha256':digest.hexdigest(),'backup':str(backup)}
    finally:
        os.close(fd)
        if temporary.is_symlink():temporary.unlink()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--active',required=True,help='Explicit absolute path of the audited active log')
    parser.add_argument('--alias',required=True,help='Explicit absolute path of its audited mirror')
    args=parser.parse_args()
    if os.geteuid()!=0:raise PermissionError('Root CLI only')
    if not Path(args.active).is_absolute() or not Path(args.alias).is_absolute():
        raise ValueError('Absolute audited paths required')
    backup_dir=Path(tempfile.mkdtemp(prefix='log-alias-',dir='/var/backups/amssoft_fail2ban')) if args.apply else Path('/var/backups/amssoft_fail2ban')
    print(json.dumps(repair(args.active,args.alias,backup_dir,args.apply)))

if __name__=='__main__':main()
