<?php
namespace AMS\Fail2Ban {class Privileged {public static function run($args){throw new \RuntimeException('Presentation test must not call native bridge');}}}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,DashboardMetadata,AIDashboard,DecisionProtection,RecentActivity};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
date_default_timezone_set('America/Sao_Paulo');$db=C::connection();$table=DashboardMetadata::TABLE;$checks=0;
function dpCheck($ok,$message){global $checks;if(!$ok)throw new \RuntimeException($message);$checks++;}
// Connection-local shadow only. DROP TEMPORARY cannot remove the production table.
$ddl=array_values((array)$db->selectOne('SHOW CREATE TABLE '.$table))[1];
$db->statement(preg_replace('/^CREATE TABLE /','CREATE TEMPORARY TABLE ',$ddl,1));
try{
 $columns=$db->select('SHOW COLUMNS FROM '.$table);$present=array_column(array_map(fn($r)=>(array)$r,$columns),'Field');
 $types=['dashboard_latest'=>'BIGINT UNSIGNED NOT NULL DEFAULT 0','dashboard_peer'=>"VARCHAR(45) NOT NULL DEFAULT ''",'dashboard_vector'=>'TINYINT NOT NULL DEFAULT 0','dashboard_learning'=>'VARCHAR(16) NULL','dashboard_refresh'=>'BIGINT UNSIGNED NULL','dashboard_revision'=>'SMALLINT UNSIGNED NOT NULL DEFAULT 0'];
 foreach($types as $name=>$type)if(!in_array($name,$present,true))$db->statement('ALTER TABLE '.$table.' ADD '.$name.' '.$type);
 if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new \RuntimeException('Cycle busy');
 $db->beginTransaction();
 try{
  Database::setConfig('schema_version','32');Database::setConfig('ai_analysis_recent_minutes','30');
  $now=time();$rows=[];$projection=['groups'=>array_fill_keys(DecisionProtection::VIEWS,[]),'states'=>[],'observed_at'=>$now];
  foreach(range(1,640) as $i){
   $ip=$i%2?'198.18.74.'.($i%200+1):'2001:db8::'.dechex($i%200+1);
   $time=$now-($i%3===0?7200:60);$target=$i%5===0?'/.git/config':'/normal';
   $line=$ip.' - - ['.date('d/M/Y:H:i:s O',$time).'] "GET '.$target.' HTTP/1.1" 404 10 "-" "fixture"';
   $result=$i%7===0?['code'=>'promotion_threshold','learning_state'=>'review']:['code'=>'fixture','learning_state'=>['pending','review','completed','none'][$i%4]];
   $r=['id'=>$i,'ip'=>$ip,'classification'=>$i%4===0?'ban':($i%2?'monitor':'whitelist'),'status'=>$i%9?'pending':'rejected',
    'jail'=>'fixture','threat'=>'presentation fixture','severity'=>'high','confidence'=>99,
    'created_at'=>date('Y-m-d H:i:s',$now-($i%50)),'resolved_at'=>null,
    'evidence'=>json_encode($i%17===0?['unknown date']:[$line]),'promotion_result'=>json_encode($result),
    'source_log'=>'/var/log/apache2/access_whmcs.log','filter_name'=>'fixture','pattern'=>hash('sha256','fixture'.$i)];
   if($i%4===0){$view=DecisionProtection::VIEWS[$i%6];$projection['groups'][$view][]=$i;
    $projection['states'][$i]=['reason'=>'fixture','eligibility'=>['latest'=>RecentActivity::latest($r),'reason'=>'fixture']];}
   $rows[]=$r+DashboardMetadata::values($r,$now);
  }
  foreach(array_chunk($rows,80) as $chunk)C::table($table)->insert($chunk);
  $requests=[2=>['last_code'=>'queued','retry_at'=>$now+300],7=>['last_code'=>'daily_limit'],999999=>['last_code'=>'orphan'],
      8=>null,'0003'=>['last_code'=>'noncanonical-key']];
  Database::setConfig('ai_rule_requests',json_encode($requests));
  $all=C::table($table)->orderByDesc('created_at')->orderByDesc('id')->get()->map(fn($r)=>(array)$r)->all();
  $observations=array_values(array_filter($all,fn($r)=>in_array($r['classification'],['monitor','whitelist'],true)));
  $stats=AIDashboard::observationStats($observations);
  foreach(AIDashboard::OBSERVATION_SCOPES as $scope)foreach(AIDashboard::LEARNING_SCOPES as $learningScope)foreach([1,3,999] as $page){
   $actual=AIDashboard::read($projection,$scope,$page,$learningScope,$page);
   $ids=array_flip($stats['groups'][$scope]);$selected=array_values(array_filter($observations,fn($r)=>isset($ids[$r['id']])));
   $pages=max(1,(int)ceil(count($selected)/10));$p=min($page,$pages);
   dpCheck($actual['read_mode']==='indexed','Indexed path not used');
   dpCheck($actual['observation_stats']===array_intersect_key($stats,array_flip(['counts','ips','undated'])),'Observation aggregate mismatch');
   dpCheck($actual['observations']['total']===count($selected)&&$actual['observations']['page']===$p&&$actual['observations']['pages']===$pages,'Observation paging mismatch');
   dpCheck(array_column($actual['observations']['data'],'id')===array_column(array_slice($selected,($p-1)*10,10),'id'),'Observation order/IDs mismatch');
   dpCheck($actual['learning']===AIDashboard::learningPage($all,$requests,$learningScope,$page),'Learning aggregate/order/data mismatch');
   dpCheck($actual['decisions']===AIDashboard::decisionStats($projection,$all),'Decision stats mismatch');
   dpCheck($actual['decision_reasons']===AIDashboard::reasonStats($projection,$all),'Decision reasons mismatch');
  }
  // Writes through the real adapter maintain metadata for new and existing proof.
  $s=['ip'=>'198.18.75.1','action'=>'monitor','severity'=>'high','confidence'=>99,'evidence'=>['198.18.75.1 - - ['.date('d/M/Y:H:i:s O',$now-60).'] "GET /.env HTTP/1.1" 404 10 "-" "fixture"'],
      'source_log'=>'/var/log/apache2/access.log','filter_name'=>'fixture-write','_pattern'=>hash('sha256','write-fixture')];
  $id=Database::saveSuggestion($s);$saved=(array)C::table($table)->where('id',$id)->first();
  dpCheck($saved['dashboard_revision']==1&&$saved['dashboard_vector']==1,'Insert metadata missing');
  $s['evidence']=['unknown date'];Database::saveSuggestion($s);$saved=(array)C::table($table)->where('id',$id)->first();
  dpCheck($saved['dashboard_latest']==0&&$saved['dashboard_vector']==0,'Updated evidence retained stale metadata');
  Database::decision($id,'fixture',['learning_state'=>'review','code'=>'promotion_threshold']);
  dpCheck(C::table($table)->where('id',$id)->value('dashboard_learning')==='criteria','Promotion metadata not updated');
  $future=$s;$future['evidence']=['198.18.75.1 - - ['.date('d/M/Y:H:i:s O',$now+900).'] "GET /.env HTTP/1.1" 404 10 "-" "fixture"'];
  $m=DashboardMetadata::values($future,$now);
  dpCheck($m['dashboard_latest']===0&&$m['dashboard_refresh']===$now+600,'Future evidence deadline lost');
  $reference=AIDashboard::read($projection,'history',999,'all',999);
  C::table($table)->where('id',1)->update(['dashboard_revision'=>0]);
  $fallback=AIDashboard::read($projection,'history',999,'all',999);
  dpCheck($fallback['read_mode']==='streamed','Unindexed metadata not detected');unset($reference['read_mode'],$fallback['read_mode'],$reference['at'],$fallback['at']);
  dpCheck($reference===$fallback,'Fallback differs from indexed output');
  C::table($table)->where('id',1)->update(['dashboard_revision'=>1,'dashboard_refresh'=>$now-1]);
  dpCheck(AIDashboard::read($projection,'all',1,'review',1)['read_mode']==='streamed','Expired future metadata ignored');
  C::table($table)->where('id',1)->update(['dashboard_refresh'=>null]);
  C::table($table)->where('id',1)->update(['dashboard_revision'=>0]);
  dpCheck(DashboardMetadata::refresh()===1,'Bounded cron catch-up failed');
  dpCheck(AIDashboard::read($projection,'all',1,'review',1)['read_mode']==='indexed','Catch-up did not restore indexed path');
  // Simulate a much larger history; all aggregate queries must remain bounded.
  $seed=$rows[0];unset($seed['id']);foreach(range(1,90) as $batch){
   $chunk=[];foreach(range(1,100) as $j)$chunk[]=$seed;C::table($table)->insert($chunk);
  }
  $db->enableQueryLog();$before=memory_get_usage(true);$start=microtime(true);
  $scaled=AIDashboard::read($projection,'all',2,'all',2);$seconds=microtime(true)-$start;$memory=memory_get_usage(true)-$before;
  $queries=$db->getQueryLog();$db->disableQueryLog();
  dpCheck(count($queries)<120,'Query amplification with non-empty production-like projection');
  dpCheck($memory<8*1048576,'History materialized in memory');
  dpCheck(count($scaled['observations']['data'])===10&&count($scaled['learning']['data'])<=10,'Oversized page');
  foreach($queries as $q)if(preg_match('/^select \* from .*mod_amssoft_fail2ban_ai_suggestions/i',$q['query']))
   dpCheck(str_contains(strtolower($q['query']),'limit 10'),'Unbounded evidence SELECT');
  Database::setConfig('dashboard_fixture_cache','before');
  try{Database::withPresentationConfigCache(function(){
   dpCheck(Database::getConfig('dashboard_fixture_cache')==='before','Initial config cache wrong');
   Database::setConfig('dashboard_fixture_cache','after');dpCheck(Database::getConfig('dashboard_fixture_cache')==='after','Write not visible in scoped cache');
   dpCheck(Database::getConfig('dashboard_fixture_missing','a')==='a'&&Database::getConfig('dashboard_fixture_missing','b')==='b','Missing default cached incorrectly');
   throw new \RuntimeException('expected-fixture-exception');
  });}catch(\RuntimeException $e){if($e->getMessage()!=='expected-fixture-exception')throw $e;}
  C::table('mod_amssoft_fail2ban_config')->where('key','dashboard_fixture_cache')->update(['value'=>'outside']);
  dpCheck(Database::getConfig('dashboard_fixture_cache')==='outside','Cache leaked outside exception scope');
  echo 'PASS: '.$checks.' dashboard pagination/index/fallback/cache checks; temporary shadow only, SQL fixtures rolled back, no API/native; queries='.count($queries).' seconds='.round($seconds,3).' memory_bytes='.$memory."\n";
 }finally{$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
}finally{$db->statement('DROP TEMPORARY TABLE '.$table);}
}
