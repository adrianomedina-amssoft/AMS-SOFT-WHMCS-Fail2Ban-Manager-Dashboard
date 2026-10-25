<?php
namespace WHMCS\Database {
 class Capsule {static function connection(){return new self;}function selectOne($s){return (object)['acquired'=>1];}static function table($t){return new Query;}}
 class Query {private $id;function __call($m,$a){return $this;}function where($k,$v){$this->id=$v;return $this;}function exists(){return false;}function first(){return (object)['analyzed_revision'=>0,'processing_state'=>\AMS\Fail2Ban\BehaviorStore::$state[$this->id]??'pending'];}}
}
namespace AMS\Fail2Ban {
require dirname(__DIR__).'/lib/CycleBudget.php';require dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
class Database {static array $cfg=[];static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}static function setConfig($k,$v){self::$cfg[$k]=$v;}static function logEvent(...$a){}}
class Policy {static function values(){return [];}static function number($k){return ['ai_cycle_seconds'=>180,'ai_call_min_budget_seconds'=>20,'ai_cycle_max_calls'=>10,'ai_retry_call_percent'=>30,'ai_queue_urgent_enabled'=>0,'global_bantime'=>3600,'ai_auto_min_confidence'=>90][$k]??0;}}
class AIAnalyzer {
 const RECOVERY_GENERATION='regex-v225-1';private $start;public bool $prepareFail=false;public int $transports=0;
 function setRequestStart(?\Closure $f):void{$this->start=$f;}function setRequestTimeout($s){}function usage(){return [];}
 function analyzeSubjects($l,$c){if($this->prepareFail)throw new CycleBudgetExceeded('Prompt preparation exhausted budget');if($this->start){$f=$this->start;$this->start=null;$f();}$this->transports++;return [['ip'=>'198.51.100.1','action'=>'ban','confidence'=>99,'threat'=>'fixture'],['ip'=>'198.51.100.2','action'=>'monitor','threat'=>'fixture']];}
}
class Fail2BanClient {}
class Safety {static function canonicalIp($s){return $s;}static function bindSuggestions($i,$p){return $i;}static function isWhitelisted(...$a){return false;}}
class BehaviorStore {
 static int $notes=0;static array $state=[],$codes=[];
 static function recoverReviews(){return 0;}static function noteAttempt($r){self::$notes++;}
 static function health(){return ['ready'=>2,'outside_window'=>0];}
 static function pending($n,$retry,...$a){return $retry?[]:array_map(fn($i)=>['ip'=>'198.51.100.'.$i,'id'=>'task'.$i,'revision'=>1,'source_log'=>'fixture','pattern'=>'fixture','events'=>1,'bucket'=>'fixture'],[1,2]);}
 static function proofEvents($r){return [];}static function campaign($p){return [];}static function history($p){return [];}
 static function validationFailed($r,$d){self::$state[$r['id']]='review';self::$codes[$r['id']]=$d['code'];}
 static function defer($r,$code='provider_partial',...$a){self::$state[$r['id']]='retry';self::$codes[$r['id']]=$code;}
}
require dirname(__DIR__).'/lib/AutoBanEngine.php';require dirname(__DIR__).'/lib/CycleAcceptance.php';require dirname(__DIR__).'/lib/QueueTelemetry.php';
class FailingEngine extends AutoBanEngine {public function saveSuggestion(array $s,string $status='pending'):int{throw new \RuntimeException('Second task processing failure');}}
$checks=0;function check($v,$m){global $checks;if(!$v)throw new \RuntimeException($m);$checks++;}
Database::$cfg=['schema_version'=>'19','ai_mode'=>'suggestion'];$scenario=$argv[1]??'all';
if(in_array($scenario,['all','preparation'])) {
 $ai=new AIAnalyzer;$ai->prepareFail=true;(new FailingEngine($ai,new Fail2BanClient))->runAnalysis();$m=QueueTelemetry::summary()['last'];
 check($ai->transports===0,'No transport after prompt preparation budget failure');
 check(BehaviorStore::$notes===0,'Prompt failure must not consume cumulative attempts');
 check($m['calls']===0&&$m['selected']===0,'Prompt failure must not count API calls or selected attempts');
}
if(in_array($scenario,['all','partial'])) {
 BehaviorStore::$notes=0;BehaviorStore::$state=BehaviorStore::$codes=[];Database::$cfg=['schema_version'=>'19','ai_mode'=>'suggestion'];$ai=new AIAnalyzer;
 (new FailingEngine($ai,new Fail2BanClient))->runAnalysis();$m=QueueTelemetry::summary()['last'];
 check(BehaviorStore::$state['task1']==='review','Later task error must preserve earlier technical review');
 check(BehaviorStore::$codes['task1']==='filter_citation','Earlier validation diagnostic must be preserved');
 check(BehaviorStore::$state['task2']==='retry'&&BehaviorStore::$codes['task2']==='provider_error','Failing unfinished task receives error backoff');
 check($m['calls']===1&&BehaviorStore::$notes===2&&$ai->transports===1,'Transport attempt is counted once for both selected tasks');
 check($m['review']===1&&$m['refused']===1,'Partial batch review/refusal counters remain consistent');
}
if(in_array($scenario,['all','acceptance'])) {
 $now=time();$m=['started_at'=>$now-30,'finished_at'=>$now,'generation'=>AIAnalyzer::RECOVERY_GENERATION,'selected'=>2,'completed'=>1,'refused'=>1,'review'=>1,'recovered'=>0,'error'=>'','calls'=>1,'retry_calls'=>0,'retry_calls_with_fresh_work'=>0,'duration_seconds'=>30.25,'reason'=>'queue_not_ready'];
 $coverage=['coverage_version'=>4,'active_jails'=>43,'missing_jail_tickets'=>0,'missing_f2b_rules'=>0,'orphan_firewall_ips'=>0,'duplicate_prefix_jails'=>0,'jails_without_actions'=>[],'jails_unverified'=>[]];$state=['status'=>'completed','started_at'=>$m['started_at'],'finished_at'=>$now];
 $valid=fn($x)=>CycleAcceptance::valid($x,$state,$coverage,$now,1,0,'',['calls'=>10,'seconds'=>180,'retry_percent'=>30]);
 check($valid($m),'Valid monotonic timing tolerates wall-clock rounding');$v=$m;$v['duration_seconds']=0;check(!$valid($v),'Incompatible duration and wall timestamps must be refused');
 foreach(['selected','completed','refused','review','recovered','started_at'] as $k){$v=$m;$v[$k]+=0.5;check(!$valid($v),'Fractional count/timestamp must be refused: '.$k);}
}
echo "PASS: {$checks} meta-review checks; simulated transport/SQL/processing, no outbound requests\n";
}
