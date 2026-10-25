import json,re,runpy,subprocess,time,unittest
from pathlib import Path
from urllib.parse import quote
from unittest.mock import patch
from fail2ban.server.failregex import FailRegex

ROOT=Path(__file__).resolve().parents[1]
H=runpy.run_path(str(ROOT/'setup/amsfb-admin'))
G=H['non_offensive_line'].__globals__
SQL="/cart.php?a=add&domain=register%22%20AND%20EXTRACTVALUE%281867%2CCONCAT%280x7e%2C%28%28SELECT%20%28ELT%281867%3D1867%2C1%29%29%29%29%2C0x7e%29%29--%20-&language=german"
def line(target,status=200,ip='198.51.100.77',tail='"-" "fixture"'):
    return f'{ip} - - [] "GET {target} HTTP/1.1" {status} 100 {tail}'
def hit(expression,record):
    expression.search([(record,'','')]);return expression.getHost() if expression.hasMatched() else None
def expression():return FailRegex(H['parse'](H['sql_filter']()).get('Definition','failregex').replace('%%','%'))

class SqlInjectionTests(unittest.TestCase):
    def test_parity_and_loaded_shape_positive_negative(self):
        queries=["x=UNION ALL SELECT 'token',NULL-- x","x=store' ORDER BY 1000-- -","x=') AND ('cweigq'='cweigq''"]
        targets=[SQL,SQL.replace('/cart.php','/index.php'),SQL.replace('%','%25')]
        for q in queries:
            targets.append('/index.php?'+quote(q,safe='=&'))
        records=[(line(t,s,ip),ip,True) for t in targets for s in [200,302,400,403,404,421,500] for ip in ['198.51.100.77','2001:db8::77']]
        negatives=['/','/index.php','/cart.php?a=add&domain=register','/index.php?note=EXTRACTVALUE','/index.php?note=ORDER%20BY%201','/index.php?note=UNION%20SELECT','/index.php?example=EXTRACTVALUE%281%29','/callback.php?invoice=100','/clientarea.php','/admin-custom/addonmodules.php']
        records += [(line(t,500,tail='"EXTRACTVALUE" "GET /cart.php?a=add UNION SELECT NULL-- -"'),None,False) for t in negatives]
        r=subprocess.run(['php',str(ROOT/'tests/sql_injection.php'),'--json'],input=json.dumps({'lines':[x[0] for x in records]}),capture_output=True,text=True,timeout=20)
        self.assertEqual(r.returncode,0,r.stderr);p=json.loads(r.stdout);self.assertEqual(p['pattern'],H['sql_query_pattern']())
        with patch.dict(G,normal_paths=lambda:['/','/index.php','/cart.php','/callback.php']):
            f=expression()
            for (record,peer,positive),php in zip(records,p['lines']):
                self.assertEqual(H['sql_target'](re.search(r'"GET ([^ ]+) HTTP/',record)[1]),positive)
                self.assertEqual(hit(f,record),peer,record)
                self.assertEqual(php['recognized'],positive,record)
                self.assertEqual(php['non_offensive'],H['non_offensive_line'](record),record)
                if positive:self.assertEqual(php['family'],'sql-injection')
        self.assertEqual(len(p['lines']),len(records))

    def test_normalizer_repairs_only_closed_own_positive_failures(self):
        bad=r'^<HOST> - \S+ \[\s*\] "GET /cart\.php\?[^ "]*EXTRACTVALUE%5C?%28[^ "]* HTTP/1\.1" 200 \d+'
        with patch.dict(G,normal_paths=lambda:['/','/index.php','/cart.php']):
            result=H['normalize_evidence_filter']({'patterns':[bad],'evidence':[line(SQL)]})
            self.assertTrue(result['closed_sql_repair']);self.assertEqual(len(result['matched_sha256']),1)
            self.assertLessEqual(len('\n'.join(result['patterns']).encode()),1000)
            f=FailRegex(result['patterns'][0]);self.assertEqual(hit(f,line(SQL)),'198.51.100.77')
            self.assertEqual(hit(f,line(SQL,ip='2001:db8::77')),'2001:db8::77')
            self.assertIsNone(hit(f,line('/index.php',tail='"-" "'+SQL+'"')))
            for evidence in [[line(SQL),line('/index.php')],[line(SQL),line(SQL,ip='198.51.100.78')],[line(SQL+'x'*1200)]]:
                with self.assertRaises(ValueError):H['normalize_evidence_filter']({'patterns':[bad],'evidence':evidence})
            with self.assertRaises(ValueError):H['normalize_evidence_filter']({'patterns':[r'^<HOST> .*'],'evidence':[line(SQL)]})

    def test_legacy_negatives_and_scope(self):
        f=expression()
        negatives=[line('/cart.php?a=add',tail='"-" "EXTRACTVALUE"'),line('/cart.php?a=add',tail='"https://example.test/EXTRACTVALUE" "fixture"'),line('/index.php',tail='"-" "GET /cart.php?a=add UNION SELECT NULL-- x"'),line('/cart.php?note=EXTRACTVALUE'),line(SQL.replace('/cart.php','/callback.php')),'prefix '+line(SQL)]
        for record in negatives:self.assertIsNone(hit(f,record),record)
        start=time.monotonic()
        for size in [800,8192,16000]:self.assertIsNone(hit(f,line('/cart.php?note='+'x'*size+'EXTRACTVALUE')))
        self.assertLess(time.monotonic()-start,2)

if __name__=='__main__':unittest.main()
