<?php
namespace AMS\Fail2Ban {
class Privileged {
 public static bool $available=true;public static array $protected=[];
 public static function run($a){
  if($a[0]==='protection-snapshot'||in_array(end($a),['ban-coverage','dashboard-protection-snapshot'],true))
   return ['success'=>self::$available,'stable'=>self::$available,'errors'=>[],'observed_at'=>time(),'requirements'=>['http'=>[80,443]],'entries'=>array_map(fn($ip)=>['ip'=>$ip,'effective'=>true,'protocol'=>'tcp','ports'=>[80,443],'jail'=>'fixture','ticket'=>'fixture','expires_at'=>time()+3600],self::$protected)];
  if($a[0]==='normalize-filter'){$p=json_decode(file_get_contents($a[1]),true);return ['success'=>true,'patterns'=>$p['patterns'],'matched_sha256'=>array_map(fn($l)=>hash('sha256',$l),$p['evidence'])];}
  if(in_array($a[0],['ensure-ai-jail','validate-filter'],true))return ['success'=>true];
  throw new \RuntimeException('Unexpected native operation: '.implode(' ',$a));
 }
}
class Fail2BanClient {public array $bans=[];public function hasEffectiveBan($j,$ip){return isset($this->bans[$ip]);}public function banIP($j,$ip){$this->bans[$ip]=$j;return true;}}
class LogLock {static function acquire($p){return ['fp'=>tmpfile(),'reason'=>null];}static function release($fp){fclose($fp);}}
}
namespace {
if(PHP_SAPI!=='cli'||empty($argv[1]))exit(1);
require $argv[1].'/configuration.php';require $argv[1].'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,Policy,BehaviorStore,ProbeApplications,AnalysisWork,QueryProbe,DecisionEligibility,DecisionProtection,AutoBanEngine,AIAnalyzer,Fail2BanClient,Privileged,ManagedRules};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();date_default_timezone_set('America/Sao_Paulo');
$created=[];$n=0;$file=null;
function dbq($ok,$why){global $n;if(!$ok)throw new RuntimeException($why);$n++;}
function ql($ip,$age,$target="/index.php?rp=/password/reset'",$status=500){static $clock=null;$clock=$clock??time();return $ip.' - - ['.date('d/M/Y:H:i:s O',$clock-$age).'] "GET '.$target.' HTTP/1.1" '.$status.' 10 "-" "fixture"';}
function qs($ip,$count=3,$confidence=96,$age=20,$source='/var/log/apache2/access_whmcs.log',$spacing=1){
 $events=[];for($i=0;$i<$count;$i++){$line=ql($ip,$age+$i*$spacing);$pattern=BehaviorStore::pattern($line);$events[]=['id'=>hash('sha256',$source.$line),'ip'=>$ip,'line'=>$line,'time'=>BehaviorStore::eventTime($line),'pattern'=>$pattern];}
 $s=['ip'=>$ip,'source_log'=>$source,'action'=>'ban','classification'=>'ban','severity'=>'high','confidence'=>$confidence,'evidence'=>array_column($events,'line'),'filter_name'=>'fixture','failregex'=>'^<HOST> fixture',
 '_pattern'=>$pattern,'_events'=>$events,'_native_validated'=>true,'_evidence_validated'=>true,'_analysis_key'=>hash('sha256',random_bytes(8)),'_task_id'=>hash('sha256',random_bytes(8))];
 $s['id']=$s['_suggestion_id']=Database::saveSuggestion($s);Database::recordDetections($s['id'],$s);return $s;
}
class QueryWorkerAI extends AIAnalyzer {
 public int $calls=0;
 public function analyzeSubjects(array $lines,array $context): array {
  $this->requestStarting();$this->calls++;$out=[];
  foreach($context as $ip=>$ctx)$out[]=['ip'=>$ip,'action'=>'ban','severity'=>'high','confidence'=>96,'threat'=>'fixture repeated query manipulation',
   'filter_name'=>'fixture-query','failregex'=>'^<HOST> fixture','evidence'=>array_values(array_filter($lines,fn($l)=>\AMS\Fail2Ban\Safety::sourceIp($l)===$ip))];
  return $out;
 }
}
try{
 // Every module table is connection-local and empty. No production row writes.
 foreach($db->select("SHOW TABLES LIKE 'mod_amssoft_fail2ban_%'") as $r){
  $table=array_values((array)$r)[0];if(!preg_match('/^mod_amssoft_fail2ban_[a-z_]+$/D',$table))throw new RuntimeException('Unknown table');
  $ddl=array_values((array)$db->selectOne('SHOW CREATE TABLE '.$table))[1];
  $db->statement(preg_replace('/^CREATE TABLE /','CREATE TEMPORARY TABLE ',$ddl,1));$created[]=$table;
 }
 foreach(Policy::fields() as $k=>$f)Database::setConfig($k,(string)$f[2]);
 foreach(['schema_version'=>'37','ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'auto','ai_auto_min_confidence'=>'90','ai_threshold_high'=>'2:60',
 'ai_auto_create_filter'=>'0','ai_whitelist_ips'=>'','ai_history_validation_per_cycle'=>'0','ai_review_auto_recovery_enabled'=>'0','ai_rule_requests'=>'{}'] as $k=>$v)Database::setConfig($k,$v);
 $s=qs('198.18.81.1');$client=new Fail2BanClient;$engine=new AutoBanEngine(null,$client);
 dbq(DecisionEligibility::queryProbe($s)['events']===3,'Validated repeats lost');
 dbq(DecisionEligibility::evaluate($s)['eligible'],'Three validated repeats not eligible');
 dbq($engine->executeBan($s)&&count($client->bans)===1,'Eligible fake ban missing');
 $single=qs('198.18.81.2',1);
 dbq(DecisionEligibility::evaluate($single)['reason']==='waiting_query_criteria','Single event became actionable');
 dbq(!$engine->executeBan($single)&&!$engine->executeBan($single,1),'Auto/manual bypass repetition');
 dbq(!$engine->approveSuggestion($single['id'],1),'UI approval bypass');
 foreach([['198.18.81.3',3,89,20],['198.18.81.4',3,99,1900]] as $args)dbq(!DecisionEligibility::queryProbe(qs(...$args))['eligible'],'Low/expired evidence passed');
 $delayed=qs('198.18.81.30',3,96,900);
 Database::setConfig('ai_mode','threshold');
 dbq(DecisionEligibility::queryProbe($delayed)['eligible']&&DecisionEligibility::evaluate($delayed)['eligible'],'15min delay lost valid burst');
 $lateClient=new Fail2BanClient;
 dbq((new AutoBanEngine(null,$lateClient))->executeBan($delayed)&&isset($lateClient->bans[$delayed['ip']]),'Delayed burst did not fake-ban');
 Database::setConfig('ai_mode','auto');
 $spaced=qs('198.18.81.31',3,99,20,'/var/log/apache2/access_whmcs.log',400);
 dbq(DecisionEligibility::queryProbe($spaced)['events']===1&&!$engine->executeBan($spaced,1),'Spaced events bypassed gate');
 $duplicate=qs('198.18.81.32',3,99,20,'/var/log/apache2/access_whmcs.log',0);
 dbq(DecisionEligibility::queryProbe($duplicate)['events']===1,'SQL duplicate proof inflation');
 Database::setConfig('ai_query_probe_decision_minutes','5');
 dbq(!DecisionEligibility::queryProbe($delayed)['eligible']&&!$engine->executeBan($delayed,1),'Configured decision age bypass');
 Database::setConfig('ai_query_probe_decision_minutes','30');Database::setConfig('ai_analysis_recent_minutes','5');
 dbq(!DecisionEligibility::queryProbe($delayed)['eligible'],'Global recency cap bypass');
 Database::setConfig('ai_analysis_recent_minutes','30');
 $rejected=qs('198.18.81.33',3,99,900);
 C::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$rejected['id'])->update(['status'=>'rejected']);
 dbq(!DecisionEligibility::queryProbe($rejected)['eligible'],'Rejected delayed evidence counted');
 dbq(!DecisionEligibility::queryProbe(qs('198.18.81.1',1,99,30,'/var/log/apache2/access_license_gateway.log'))['eligible'],'Other source inherited proof');
 Database::setConfig('ai_query_probe_enabled','0');dbq(!$engine->executeBan($s,1)&&!DecisionEligibility::evaluate($s)['eligible'],'Disabled fell through auto');
 Database::setConfig('ai_query_probe_enabled','1');Database::setConfig('ai_query_probe_min_events','4');
 dbq(!DecisionEligibility::queryProbe($s)['eligible'],'UI threshold ignored');Database::setConfig('ai_query_probe_min_events','3');
 Database::setConfig('ai_auto_min_confidence','50');dbq(!DecisionEligibility::queryProbe(qs('198.18.81.5',3,89))['eligible'],'90 floor bypassed');Database::setConfig('ai_auto_min_confidence','90');
 Database::setConfig('ai_whitelist_ips',$s['ip']);dbq(!$engine->executeBan($s),'Whitelist bypass');Database::setConfig('ai_whitelist_ips','');
 Privileged::$available=false;dbq(!$engine->executeBan(qs('198.18.81.6')),'Unknown protection bypass');Privileged::$available=true;
 Privileged::$protected=[$s['ip']];$previous=count($client->bans);dbq($engine->executeBan($s)&&count($client->bans)===$previous,'Existing ban renewed');Privileged::$protected=[];
 dbq(ManagedRules::promote($s,$client,1,false)['code']==='query_behavior_only','Learning bypassed behavioral criteria');
 // Real worker with only this temporary-table task. Provider and firewall are mocks.
 $ip='198.18.81.10';$events=[];for($i=0;$i<5;$i++){$line=ql($ip,900+$i);$pattern=BehaviorStore::pattern($line);$events[]=['id'=>hash('sha256',$line),'ip'=>$ip,'line'=>$line,'time'=>BehaviorStore::eventTime($line),'pattern'=>$pattern];}
 $task=hash('sha256','worker-query-fixture');
 C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$task,'ip'=>$ip,'source_log'=>'/var/log/apache2/access_whmcs.log','pattern'=>$pattern,'bucket'=>date('Y-m-d H:i:s',time()-1200),
 'last_event_at'=>date('Y-m-d H:i:s',time()-900),'events'=>5,'revision'=>1,'samples'=>json_encode($events)]);
 $ai=new QueryWorkerAI('openai','fixture');$wc=new Fail2BanClient;
 Database::setConfig('ai_mode','threshold');
 (new AutoBanEngine($ai,$wc))->runAnalysis();
 dbq($ai->calls===1,'Worker did not call simulated provider once');
 dbq(isset($wc->bans[$ip]),'Worker failed to validate and fake-ban query case');
 $saved=C::table('mod_amssoft_fail2ban_ai_suggestions')->where('ip',$ip)->first();
 dbq($saved&&$saved->classification==='ban'&&$saved->decision_code==='blocked','Worker downgraded query');
 $protectedIp='198.18.81.11';$protectedEvents=[];
 for($i=0;$i<5;$i++){$line=ql($protectedIp,10+$i);$protectedEvents[]=['id'=>hash('sha256',$line),'ip'=>$protectedIp,'line'=>$line,'time'=>BehaviorStore::eventTime($line),'pattern'=>BehaviorStore::pattern($line)];}
 C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>hash('sha256','protected-query-fixture'),'ip'=>$protectedIp,'source_log'=>'/var/log/apache2/access_whmcs.log','pattern'=>$protectedEvents[0]['pattern'],
 'bucket'=>date('Y-m-d H:i:s',time()-60),'last_event_at'=>date('Y-m-d H:i:s',time()-10),'events'=>5,'revision'=>1,'samples'=>json_encode($protectedEvents)]);
 Privileged::$protected=[$protectedIp];\AMS\Fail2Ban\BlockedTasks::invalidate();
 $protectedAI=new QueryWorkerAI('openai','fixture');(new AutoBanEngine($protectedAI,new Fail2BanClient))->runAnalysis();
 dbq($protectedAI->calls===0,'Protected IP consumed provider tokens');Privileged::$protected=[];
 // Incremental real collector, private log and temporary cursor.
 Database::setConfig('ai_behavior_enabled','0');$file=tempnam('/tmp','amsfb-query-collector-');
 dbq(BehaviorStore::collect($file)['mode']==='initialized_at_eof','Private cursor init');
 $paths=['/solr/','/sugar_version.json',...array_fill(0,5,'/cgi-bin/authLogin.cgi')];$rows=[];
 foreach($paths as $i=>$path)$rows[]=ql('198.18.81.20',20-$i,$path,404);
 file_put_contents($file,implode("\n",array_slice($rows,0,3))."\n");BehaviorStore::collect($file);
 file_put_contents($file,implode("\n",array_slice($rows,3))."\n",FILE_APPEND);BehaviorStore::collect($file);
 $r=(array)C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$file)->first();
 dbq((int)$r['events']===7,'Collector lost count');
 $samples=json_decode($r['samples'],true);
 dbq(count($samples)===5&&ProbeApplications::stats($samples,$r['ip'])['applications']===3,'Collector lost diversity');
 $work=AnalysisWork::consolidateRows([$r],[],time(),time()-1800)[0];
 dbq(count($work['_work_events']??[])===5,'Retained signatures not complete');
 dbq(BehaviorStore::collect($file)['events']===0,'Cursor reread');
 echo "PASS: {$n} isolated SQL, worker, ban-gate and collector checks; no production row writes, provider or firewall calls\n";
}finally{
 if($file&&is_file($file))unlink($file);
 foreach(array_reverse($created) as $table)$db->statement('DROP TEMPORARY TABLE IF EXISTS '.$table);
}
}
