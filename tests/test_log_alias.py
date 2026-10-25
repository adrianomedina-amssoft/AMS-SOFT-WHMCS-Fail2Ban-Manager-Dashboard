import hashlib
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

REPAIR=runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/repair_log_alias.py'))['repair']

class AliasTests(unittest.TestCase):
    def test_detach_preserves_inode_bytes_and_mirror(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);active=root/'active.log';alias=root/'mirror.log';active.write_bytes(b'preserved log\n');os.link(active,alias)
            inode=active.stat().st_ino
            self.assertTrue(REPAIR(active,alias,root)['dry_run']);self.assertEqual(active.stat().st_nlink,2)
            result=REPAIR(active,alias,root,True)
            self.assertEqual(active.stat().st_ino,inode);self.assertEqual(active.stat().st_nlink,1)
            self.assertTrue(alias.is_symlink());self.assertEqual(alias.read_bytes(),b'preserved log\n')
            self.assertEqual(hashlib.sha256(Path(result['backup']).read_bytes()).hexdigest(),result['sha256'])
            self.assertFalse(REPAIR(active,alias,root,True)['changed'])
            active.write_bytes(b'new log\n');self.assertEqual(alias.read_bytes(),b'new log\n')
    def test_refuse_unrelated_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);a=root/'a';b=root/'b';a.write_bytes(b'a');b.write_bytes(b'b')
            with self.assertRaises(ValueError):REPAIR(a,b,root,True)
            self.assertEqual(b.read_bytes(),b'b')
    def test_refuse_extra_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);a=root/'a';b=root/'b';a.write_bytes(b'a');os.link(a,b);os.link(a,root/'c')
            with self.assertRaises(ValueError):REPAIR(a,b,root,True)
            self.assertEqual(a.stat().st_nlink,3)
    def test_concurrent_alias_change_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);a=root/'a';b=root/'b';a.write_bytes(b'active');os.link(a,b);inode=a.stat().st_ino
            create=os.symlink
            def race(target,link):
                create(target,link);b.unlink();b.write_bytes(b'external replacement')
            with patch.object(os,'symlink',side_effect=race),self.assertRaises(ValueError):
                REPAIR(a,b,root,True)
            self.assertEqual(a.stat().st_ino,inode);self.assertEqual(a.read_bytes(),b'active')
            self.assertEqual(b.read_bytes(),b'external replacement')

if __name__=='__main__':unittest.main()
