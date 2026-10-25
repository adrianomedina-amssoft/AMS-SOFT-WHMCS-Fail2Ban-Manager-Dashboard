import importlib.util
from pathlib import Path
import unittest
from fail2ban.server.failregex import FailRegex
from fail2ban.server.datedetector import DateDetector

spec=importlib.util.spec_from_file_location('repair',Path(__file__).resolve().parents[1]/'scripts/repair_recent_coverage.py')
repair=importlib.util.module_from_spec(spec);spec.loader.exec_module(repair)

class RecentCoverage(unittest.TestCase):
    def matches(self,path,status=404,method='GET',pattern=None):
        line='198.51.100.77 - - [14/Oct/2026:23:12:01 -0300] "'+method+' '+path+' HTTP/1.1" '+str(status)+' 123 "-" "test"'
        d=DateDetector();d.addDefaultTemplate();m=d.matchTime(line)[0]
        split=(line[:m.start(1)],line[m.start(1):m.end(1)],line[m.end(1):])
        r=FailRegex(pattern or repair.literal_pattern(['/.env','/.git/config','/.svn/wc.db']))
        r.search([split]);return r.getHost() if r.hasMatched() else None
    def test_literal_positive_exact_peer(self):
        for p in ['/.env','/.git/config','/.svn/wc.db','/.env?lang=pt']:
            self.assertEqual(self.matches(p),'198.51.100.77')
    def test_legitimate_and_wrong_status(self):
        for p in ['/index.php','/checkout.php','/.env.example','/.envx','/x/.env']:
            self.assertIsNone(self.matches(p))
        self.assertIsNone(self.matches('/.env',200));self.assertIsNone(self.matches('/.env',404,'POST'))
    def test_literals_not_regex_injection(self):
        p=repair.literal_pattern(['/a+.env'])
        self.assertEqual(self.matches('/a+.env',pattern=p),'198.51.100.77')
        self.assertIsNone(self.matches('/aaaa.env',pattern=p))
    def test_grouping_not_ssl_or_normal_route(self):
        self.assertEqual(repair.classify_path('/.svn/wc.db'),'amsfb-apache-git-probe')
        self.assertEqual(repair.classify_path('/core/install.php'),'amsfb-apache-cms-probe')
        for p in ['/checkout.php','/AH02032','/license.php']:
            self.assertIsNone(repair.classify_path(p))

if __name__=='__main__':unittest.main()
