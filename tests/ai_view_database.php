<?php
namespace AMS\Fail2Ban {
class Privileged {static array $snapshot=[];static int $calls=0;static function run($args){self::$calls++;if($args!==['--read-budget','15','dashboard-protection-snapshot'])throw new \RuntimeException('Unexpected native command');return self::$snapshot;}}
class DecisionEligibility {static function evaluate($r){return ['view'=>'actionable','reason'=>'fixture','latest'=>time(),'eligible'=>true];}}
class DecisionMemory {static function policyFingerprint(){return 'fixture';}}
}
namespace {
if(PHP_SAPI!=='cli'||($argv[1]??'')==='')exit(1);
require $argv[1].'/configuration.php';require $argv[1].'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{AIView as V,DecisionProtection as D,Privileged as P,Database};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();date_default_timezone_set('America/Sao_Paulo');
$tables=['mod_amssoft_fail2ban_ai_suggestions','mod_amssoft_fail2ban_geo_cache','mod_amssoft_fail2ban_decision_state','mod_amssoft_fail2ban_evidence_links'];$created=[];$n=0;
function db48($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
try{
 foreach($tables as $table){$ddl=array_values((array)$db->selectOne('SHOW CREATE TABLE '.$table))[1];$db->statement(preg_replace('/^CREATE TABLE /','CREATE TEMPORARY TABLE ',$ddl,1));$created[]=$table;}
 $now=time();$rows=[];for($i=1;$i<=55;$i++)$rows[]=['id'=>$i,'ip'=>$i<3?'198.51.100.1':'198.51.100.'.$i,'status'=>'pending','classification'=>'ban','source_log'=>'/var/log/apache2/access_whmcs.log','threat'=>'fixture','severity'=>'high','confidence'=>99,'created_at'=>date('Y-m-d H:i:s',$now),'decision_code'=>'fixture'];
 C::table($tables[0])->insert($rows);
 C::table($tables[1])->insert([
 ['ip'=>'198.51.100.1','country_code'=>'BR','country'=>'Brasil','updated_at'=>date('Y-m-d H:i:s',$now)],
 ['ip'=>'198.51.100.3','country_code'=>'BR','country'=>'Brasil','updated_at'=>date('Y-m-d H:i:s',$now)],
 ['ip'=>'198.51.100.4','country_code'=>'US','country'=>'United States','updated_at'=>date('Y-m-d H:i:s',$now-31*86400)]]);
 C::table($tables[3])->insert([['suggestion_id'=>3,'fingerprint'=>str_repeat('a',64),'confidence'=>99,'validation_state'=>'valid','origin'=>'fixture'],['suggestion_id'=>3,'fingerprint'=>str_repeat('b',64),'confidence'=>99,'validation_state'=>'unknown','origin'=>'fixture']]);
 $snap=['success'=>true,'stable'=>true,'observed_at'=>$now,'errors'=>[],'requirements'=>['http'=>[80,443]],'entries'=>[['ip'=>'198.51.100.1','protocol'=>'tcp','ports'=>[80,443],'effective'=>true,'expires_at'=>$now+3600,'jail'=>'fixture','ticket'=>'fixture']]];
 P::$snapshot=$snap;
 $db->statement('SET TRANSACTION READ ONLY');$db->beginTransaction();$db->enableQueryLog();
 $projection=Database::withPresentationConfigCache(fn()=>V::projection());
 db48(count($projection['groups']['protected'])===2&&count($projection['groups']['actionable'])===53,'Protected excluded before paging');
 db48(C::table($tables[2])->count()===0,'No persisted projection');
 $page=V::pending($projection,'actionable',1);db48(array_column($page['data'],'id')===range(55,46),'Stable descending ID tie break');
 $last=V::pending($projection,'actionable',999);db48($last['page']===6&&$last['total']===53&&count($last['data'])===3,'Clamp and global total');
 $history=V::history(['severity'=>'high'],2);db48(array_column($history['data'],'id')===range(45,36)&&$history['total']===55,'Stable history order');
 db48(V::history(['severity'=>'low'],1)['total']===0,'Exact history filter');
 $groups=V::countries($projection);$countries=array_column($groups,'ip_count','country_code');db48((int)$countries['BR']===1&&(int)$countries['']===52,'Same projection and fresh cache for countries');
 db48(V::countryIds('US')['ids']===[]&&V::countryIds('BR')['ids']===[3],'Stale country not selected, protected not selected');
 db48(count(V::countryIds('')['ids'])===52,'Unknown country includes expired cache');
 db48(V::proofCounts([['id'=>3]])===[3=>['unknown'=>1,'valid'=>1]]||V::proofCounts([['id'=>3]])===[3=>['valid'=>1,'unknown'=>1]],'Grouped proof counts');
 P::$snapshot=['success'=>false,'errors'=>['unavailable']];$unknown=Database::withPresentationConfigCache(fn()=>V::projection());
 db48(count($unknown['groups']['checking'])===55&&$unknown['groups']['actionable']===[],'Failed native read is checking, never actionable');
 P::$snapshot=$snap;P::$snapshot['observed_at']=$now-86400;
 try{Database::withPresentationConfigCache(fn()=>V::projection());db48(false,'Expired accepted');}catch(RuntimeException $e){db48(true,'Expired success refused');}
 foreach($db->getQueryLog() as $q)db48((bool)preg_match('/^\s*(select|show)/i',$q['query']),'Read-only SQL');
 $db->rollBack();$db->disableQueryLog();
 // Only the connection-local shadow receives scalability fixtures.
 $seed=$rows[2];unset($seed['id']);for($i=0;$i<50;$i++)C::table($tables[0])->insert(array_fill(0,100,$seed));$before=P::$calls;
 try{V::projection();db48(false,'Oversized accepted');}catch(RuntimeException $e){db48(P::$calls===$before,'Limit refuses before native read');}
 db48(C::table($tables[2])->count()===0,'Still no state writes');
 echo "PASS: $n AI SQL projection/pagination/country/proof checks; temporary tables only, native mocked\n";
}finally{if($db->transactionLevel())$db->rollBack();foreach(array_reverse($created) as $table)$db->statement('DROP TEMPORARY TABLE IF EXISTS '.$table);}
}
