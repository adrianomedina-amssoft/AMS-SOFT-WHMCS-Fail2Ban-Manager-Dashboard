<?php
namespace WHMCS\Database {
    class Capsule {static function connection(){return new self;} function selectOne($s){return (object)['acquired'=>1];} static function table($t){return new Query;}}
    class Query {private $id;function __call($m,$a){return $this;}function where($k,$v){$this->id=$v;return $this;}function exists(){return false;}function first(){return (object)['analyzed_revision'=>isset(\AMS\Fail2Ban\BehaviorStore::$done[$this->id])?1:0,'processing_state'=>'pending'];}}
}
namespace AMS\Fail2Ban {
require dirname(__DIR__).'/lib/CycleBudget.php';require dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
class Database {public static array $cfg=[];static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}static function setConfig($k,$v){self::$cfg[$k]=$v;}static function logEvent(...$a){} }
class Policy {static function values(){return [];}static function number($k){return ['ai_cycle_seconds'=>180,'ai_call_min_budget_seconds'=>20,'ai_cycle_max_calls'=>10,'ai_retry_call_percent'=>30,'ai_queue_urgent_enabled'=>0,'global_bantime'=>3600][$k]??0;}}
class AIAnalyzer {
 private $start;function setRequestStart(?\Closure $f):void{$this->start=$f;}
 const RECOVERY_GENERATION='regex-v225-1';public int $calls=0,$timeout=90;
 function setRequestTimeout($s){$this->timeout=$s;}function usage(){return [];}
 function analyzeSubjects($l,$c){if($this->start){$f=$this->start;$this->start=null;$f();}$this->calls++;FixtureClock::$now+=min(90,$this->timeout);$out=[];foreach($c as $ip=>$v)$out[]=['ip'=>$ip,'action'=>'monitor','threat'=>'fixture'];return $out;}
}
class Fail2BanClient {}
class Safety {static function canonicalIp($s){return $s;}static function bindSuggestions($i,$p){return $i;}}
class BehaviorStore {
 static array $done=[];static int $notes=0,$defers=0,$preparation=0;
 static function recoverReviews(){return 0;}static function noteAttempt($r){self::$notes++;}
 static function pending($limit=10,$retry=null,...$a){if($retry)return [];return array_values(array_filter(self::rows(),fn($r)=>!isset(self::$done[$r['id']])));}
 static function rows(){return array_map(fn($i)=>['ip'=>'198.51.100.'.$i,'id'=>'fixture'.$i,'revision'=>1,'source_log'=>'fixture','pattern'=>'fixture','events'=>1,'bucket'=>'fixture'],range(1,10));}
 static function proofEvents($r){return [];}static function campaign($p){return [];}
 static function history($p){if(self::$preparation){FixtureClock::$now+=self::$preparation;self::$preparation=0;}return [];}
 static function acknowledge($r){self::$done[$r['id']]=true;}static function defer(...$a){self::$defers++;}static function health(){return ['new'=>10,'retry'=>10,'ready'=>20-count(self::$done),'outside_window'=>0];}
}
class FixtureClock {static float $now=0;}
require dirname(__DIR__).'/lib/QueueTelemetry.php';require dirname(__DIR__).'/lib/AutoBanEngine.php';require dirname(__DIR__).'/lib/CycleAcceptance.php';
class FixtureEngine extends AutoBanEngine {public bool $abort=false;public function saveSuggestion(array $s,string $status='pending'):int {if($this->abort)throw new CycleBudgetExceeded('Simulated validation deadline');FixtureClock::$now+=10;return 1;}}
$checks=0;function check($v,$m){global $checks;if(!$v)throw new \RuntimeException($m);$checks++;}
$clock=new \ReflectionProperty(CycleBudget::class,'clock');$clock->setAccessible(true);$clock->setValue(null,fn()=>FixtureClock::$now);
function resetFixture(){FixtureClock::$now=0;BehaviorStore::$done=[];BehaviorStore::$notes=BehaviorStore::$defers=BehaviorStore::$preparation=0;Database::$cfg=['schema_version'=>'19','ai_mode'=>'suggestion'];CycleBudget::end();}
try {
 resetFixture();CycleBudget::begin(180);check(CycleBudget::timeout(90,47)===90,'API timeout cap');FixtureClock::$now=170;
 check(CycleBudget::timeout()===8,'Read timeout uses remainder and margin');
 try{CycleBudget::requireTime(47);check(false,'Mutation must wait for next cycle');}catch(CycleBudgetExceeded $e){check(true,'Mutation reserve enforced');}
 FixtureClock::$now=179;try{CycleBudget::timeout();check(false,'Expired read');}catch(CycleBudgetExceeded $e){check(true,'No read without budget');}CycleBudget::end();
 resetFixture();CycleBudget::begin(30,2);check(CycleBudget::timeout(90,CycleBudget::providerReserve())===28,'Suggestion-only short cycle has no mutation reserve');CycleBudget::end();
 resetFixture();$ai=new AIAnalyzer;$e=new FixtureEngine($ai,new Fail2BanClient);$e->runAnalysis();$t=QueueTelemetry::summary();
 check($ai->calls===1&&count(BehaviorStore::$done)===9,'Stops processing batch after API when budget ends');
 check(BehaviorStore::$defers===0&&$t['last']['error']==='','Budget stop is not provider or validation failure');
 check($t['last']['reason']==='time_limit'&&!CycleBudget::active(),'Reason and cleanup');
 check(!isset(BehaviorStore::$done['fixture10']),'Unprocessed task stays pending');
 resetFixture();BehaviorStore::$preparation=170;$ai=new AIAnalyzer;(new FixtureEngine($ai,new Fail2BanClient))->runAnalysis();
 check($ai->calls===0&&BehaviorStore::$notes===0,'Preparation consumes budget before attempt/API');
 check(QueueTelemetry::summary()['last']['selected']===0,'Unstarted selection is not counted');
 resetFixture();$ai=new AIAnalyzer;$e=new FixtureEngine($ai,new Fail2BanClient);$e->abort=true;$e->runAnalysis();
 check(BehaviorStore::$done===[]&&BehaviorStore::$defers===0,'Validation budget exception preserves tasks and backoff');
 check(QueueTelemetry::summary()['state']['status']==='completed','Budget exhaustion completes cycle normally');
 resetFixture();$now=time();$m=['started_at'=>$now-30,'finished_at'=>$now,'generation'=>AIAnalyzer::RECOVERY_GENERATION,'selected'=>10,'completed'=>6,'refused'=>2,'review'=>1,'recovered'=>1,'error'=>'','calls'=>1,'retry_calls'=>0,'retry_calls_with_fresh_work'=>0,'duration_seconds'=>30.0,'reason'=>'queue_not_ready'];
 $bad=$m;$bad['error']='provider_or_processing';$bad['reason']='error';
 Database::$cfg['ai_cycle_metrics']=json_encode([$bad+['entries_since_previous'=>null],$bad+['entries_since_previous'=>3,'expired_since_previous'=>0],$bad+['entries_since_previous'=>3,'expired_since_previous'=>0]]);
 check(QueueTelemetry::summary()['capacity']==='insufficient_data'&&QueueTelemetry::summary()['cycles']===0,'Error-only history never estimates draining');
 $success=$m+['entries_since_previous'=>3,'expired_since_previous'=>0,'eligible_ready_start'=>10,'eligible_ready_end'=>4,'eligible_comparable'=>true];
 Database::$cfg['ai_cycle_metrics']=json_encode([$success,$success,$bad,$success,$success]);
 check(QueueTelemetry::summary()['estimated_cycles']===null,'Two successes after failure have only one interval');
 Database::$cfg['ai_cycle_metrics']=json_encode([$success,$bad,$success,$success,$success]);
 check(QueueTelemetry::summary()['capacity']==='draining'&&QueueTelemetry::summary()['completed']===12,'Two intact success intervals restore measured trend');
 $coverage=['coverage_version'=>4,'active_jails'=>43,'missing_jail_tickets'=>0,'missing_f2b_rules'=>0,'orphan_firewall_ips'=>0,'duplicate_prefix_jails'=>0,'jails_without_actions'=>[],'jails_unverified'=>[]];
 $state=['status'=>'completed','started_at'=>$m['started_at'],'finished_at'=>$m['finished_at']];$limits=['calls'=>10,'seconds'=>180,'retry_percent'=>30];
 $valid=fn($metric,$cover=null,$st=null)=>CycleAcceptance::valid($metric,$st??$state,$cover??$coverage,$now,$metric['calls'],$metric['retry_calls'],'',$limits);
 check($valid($m),'Complete measured cycle accepted');$v=$m;$v['duration_seconds']=180.001;check(!$valid($v),'Exceeded duration refused');
 foreach(['duration_seconds','retry_calls_with_fresh_work','selected'] as $key){$v=$m;unset($v[$key]);check(!$valid($v),'Missing metric refused: '.$key);}
 $v=$coverage;unset($v['jails_unverified']);check(!$valid($m,$v),'Absent coverage list is not an empty measurement');
 $v=$m;$v['calls']=8;$v['retry_calls']=4;check($valid($v),'Retry calls without fresh work may use remaining budget');
 $v['retry_calls_with_fresh_work']=4;check(!$valid($v),'Retry quota with fresh work enforced');
 $v=$m;$v['completed']=9;check(!$valid($v),'Inconsistent result counts refused');
 $v=$m;$v['generation']='wrong';check(!$valid($v),'Wrong generation refused');
 $v=$state;$v['status']='error';check(!$valid($m,$coverage,$v),'Failed state refused');
 check(!CycleAcceptance::valid($m,$state,$coverage,$now,2,0,'',$limits),'Legacy counters must match metrics');
}finally{CycleBudget::end();$clock->setValue(null,null);}
echo "PASS: {$checks} review runtime/telemetry/acceptance checks; memory-only\n";
}
