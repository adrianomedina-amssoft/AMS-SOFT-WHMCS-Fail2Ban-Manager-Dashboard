import json,runpy,subprocess,time,unittest
from pathlib import Path
from urllib.parse import quote
from fail2ban.server.failregex import FailRegex

ROOT=Path(__file__).resolve().parents[1]
H=runpy.run_path(str(ROOT/'setup/amsfb-admin'))
ROUTE='/modules/addons/RSThemes/src/Api/clientApi.php'
def line(target,ip='198.51.100.77',status=404,tail='"-" "fixture"'):
    return f'{ip} - - [] "GET {target} HTTP/1.1" {status} 10 {tail}'
def expr(group,enabled=True):
    return FailRegex(H['parse'](H['sensitive_filter']([group],enabled)).get('Definition','failregex').replace('%%','%'))
def peer(regex,record):
    regex.search([(record,'','')])
    return regex.getHost() if regex.hasMatched() else None

class ObfuscatedSqlTests(unittest.TestCase):
    def test_php_helper_native_parity_and_php_gate(self):
        payloads=["StockControl')/*!And*/4222/*!BETWEEN*/9695/*!AND*/9695--/**/x",
                  "x/*!OR*//*!NOT*/9832/*!between*/9832/*!and*/9832",
                  "x/*!where*/42=42/*!or*/5=5",
                  "x%00/*!AND*/123=123",
                  "x/*!RLIKE*/(/*!SELECT*/(/*!CASE*//*!WHEN*/(2351=2351)/*!THEN*/'StockControl'/*!ELSE*/0x28/*!END*/))"]
        records=[]
        native=expr('sql_obfuscated')
        for payload in payloads:
            for variant in (payload,quote(payload,safe=''),quote(quote(payload,safe=''),safe='')):
                for path in (ROUTE,'/index.php','/cart.php'):
                    for ip in ('198.51.100.77','2001:db8::77'):
                        for status in (200,301,302,400,403,404,421,500):
                            record=line(path+'?controller='+variant,ip,status)
                            self.assertEqual(peer(native,record),ip)
                            self.assertTrue(H['sql_target'](path+'?controller='+variant))
                            records.append(record)
        p=subprocess.run(['php',str(ROOT/'tests/sql_obfuscated.php'),'--json'],input=json.dumps(records),text=True,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stderr)
        result=json.loads(p.stdout)
        self.assertEqual(result['pattern'],H['sql_obfuscated_pattern']())
        for row in result['rows']:
            self.assertTrue(row['sql']);self.assertEqual(row['family'],'sql-injection');self.assertIsNone(row['php_path']);self.assertFalse(row['normal'])

    def test_negative_and_scope_and_opt_out(self):
        payload="x/*!AND*/123=123"
        f=expr('sql_obfuscated')
        for target in (ROUTE,ROUTE+'?controller=StockControl&method=getStockControl&id=1',
                       ROUTE+'?controller=6583',ROUTE+'?q=AND',ROUTE+'?q=BETWEEN',
                       ROUTE+'?q=/*!AND*/',ROUTE+'?q=/*!AND*/123',
                       '/callback.php?x='+payload,'/prefix'+ROUTE+'?x='+payload,
                       ROUTE.lower()+'?x='+payload,ROUTE+'/child?x='+payload,
                       '/index.php?x=/*AND*/1=1','/index.php?x=/*!CASE*//*!WHEN*/',
                       '/index.php?x=/*!AND*/'+'1'*13+'=2'):
            self.assertIsNone(peer(f,line(target,tail='"'+ROUTE+'?x='+payload+'" "'+payload+'"')),target)
        record=line(ROUTE+'?x='+payload)
        for group in ('env','sql_injection'):
            self.assertIsNone(peer(expr(group),record))
        self.assertIsNone(peer(expr('sql_obfuscated',False),record))
        self.assertIsNone(peer(f,'prefix '+record))
        start=time.monotonic()
        for size in (8000,16000,64000):
            self.assertIsNone(peer(f,line('/index.php?x='+'a'*size+'/*!AND*/')))
        self.assertLess(time.monotonic()-start,2)

    def test_admin_exact_trap(self):
        f=expr('admin_config_probe')
        for ip in ('198.51.100.77','2001:db8::77'):
            for status in (200,301,403,404,500):
                for target in ('/admin/config.php','/admin/config.php?x=1'):
                    self.assertEqual(peer(f,line(target,ip,status)),ip)
        for target in ('/admin-custom/config.php','/admin/config.php.bak','/admin/config.php/child',
                       '/ADMIN/config.php','/x/admin/config.php','/config.php','/index.php?q=/admin/config.php'):
            self.assertIsNone(peer(f,line(target,tail='"/admin/config.php" "GET /admin/config.php"')))
        self.assertIsNone(peer(expr('admin_config_probe',False),line('/admin/config.php')))

if __name__=='__main__':unittest.main()
