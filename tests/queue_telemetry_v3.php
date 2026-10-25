<?php
namespace WHMCS\Database {
class Capsule {public static array $rows=[];public static bool $fail=false;public static int $reads=0;public static function table($t){return new Query;}}
class Query {
 private array $conditions=[];private int $limit=PHP_INT_MAX;
 public function where($field,$op=null,$value=null){return $this->condition(false,$field,$op,$value);}
 public function orWhere($field,$op=null,$value=null){return $this->condition(true,$field,$op,$value);}
 private function condition($or,$field,$op,$value){
  if($field instanceof \Closure){$q=new self;$field($q);$test=fn($r)=>$q->matches($r);}
  else{$test=fn($r)=>match($op){'>'=>($r[$field]??null)>$value,'>='=>($r[$field]??null)!==null&&$r[$field]>=$value,'<='=>($r[$field]??null)!==null&&$r[$field]<=$value,'!='=>($r[$field]??null)!=$value,default=>throw new \RuntimeException('Unsupported operator')};}
  $this->conditions[]=[$or,$test];return $this;
 }
 public function whereNull($key){$this->conditions[]=[false,fn($r)=>($r[$key]??null)===null];return $this;}
 public function whereColumn($left,$op,$right){$this->conditions[]=[false,fn($r)=>$r[$left]>$r[$right]];return $this;}
 public function orderBy($k){return $this;}
 public function limit($n){$this->limit=$n;return $this;}
 public function matches($r){$v=null;foreach($this->conditions as [$or,$test]){$x=$test($r);$v=$v===null?$x:($or?$v||$x:$v&&$x);}return $v??true;}
 public function get($columns){Capsule::$reads++;if(Capsule::$fail)throw new \RuntimeException('Read unavailable');$rows=[];foreach(Capsule::$rows as $r)if($this->matches($r))$rows[]=(object)array_intersect_key($r,array_flip($columns));$rows=array_slice($rows,0,$this->limit);return new class($rows){public function __construct(private array $rows){}public function all(){return $this->rows;}};}
}
}
namespace AMS\Fail2Ban {
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=['schema_version'=>'37'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}public static function setConfig($k,$v){self::$cfg[$k]=$v;}}
class Policy {public static function number($k){return ['ai_analysis_recent_minutes'=>30,'ai_behavior_hours'=>24][$k];}}
class DecisionMemory {public static function policyFingerprint(){return 'cohort-fixture';}}
require dirname(__DIR__).'/lib/QueueCohort.php';require dirname(__DIR__).'/lib/QueueTelemetry.php';
date_default_timezone_set('America/Sao_Paulo');$n=0;
function tc($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
$now=time();
function row($name,array $override=[]){global $now;return array_replace(['id'=>hash('sha256',$name),'revision'=>2,'analyzed_revision'=>1,'bucket'=>date('Y-m-d H:i:s',$now-1800),'last_event_at'=>date('Y-m-d H:i:s',$now-1790),'processing_state'=>'pending','blocked_confirmed_at'=>null,'blocked_until_check_at'=>null,'retry_at'=>null],$override);}
$ready=row('ready');$done=row('old-completed',['analyzed_revision'=>2]);
$held=row('held',['blocked_confirmed_at'=>date('Y-m-d H:i:s',$now-10),'blocked_until_check_at'=>date('Y-m-d H:i:s',$now+10)]);
$staleHeld=row('held-stale',['blocked_confirmed_at'=>date('Y-m-d H:i:s',$now-500),'blocked_until_check_at'=>date('Y-m-d H:i:s',$now-1)]);
$review=row('review',['processing_state'=>'review']);$retry=row('backoff',['processing_state'=>'retry','retry_at'=>date('Y-m-d H:i:s',$now+10)]);
$cold=row('cold',['last_event_at'=>date('Y-m-d H:i:s',$now-1801)]);
$outside=row('outside',['bucket'=>date('Y-m-d H:i:s',$now-86401)]);
$future=row('future',['last_event_at'=>date('Y-m-d H:i:s',$now+301)]);
\WHMCS\Database\Capsule::$rows=[$ready,$done,$held,$staleHeld,$review,$retry,$cold,$outside,$future];
$cohort=QueueCohort::capture($now,1);
tc($cohort['complete']&&array_keys($cohort['tasks'])===[$ready['id']],'Only initially ready unfinished task participates');
tc($cohort['tasks'][$ready['id']]['revision']===2,'Revision identity retained');
foreach([$done,$held,$staleHeld,$review,$retry,$cold,$outside,$future] as $excluded)tc(!isset($cohort['tasks'][$excluded['id']]),'Excluded state cannot invalidate metric');
tc(QueueCohort::crossed($cohort,$now+10)===false,'Exact expiry boundary still eligible');
tc(QueueCohort::crossed($cohort,$now+11)===true,'Pending task crossed original deadline');
\WHMCS\Database\Capsule::$rows=[$done];
tc(QueueCohort::crossed($cohort,$now+11)===true,'Completion/deletion at end cannot erase original crossing');
$empty=QueueCohort::capture($now,0);tc(QueueCohort::crossed($empty,$now+11)===false,'Previously completed tasks never invalidate empty cohort');
tc(QueueCohort::crossed($empty,$now-1)===null,'Clock reversal cannot assert comparison');
tc(QueueCohort::crossed(null,$now)===null,'Missing snapshot unknown, not false');
tc(QueueCohort::crossed(['complete'=>false],$now)===null,'Incomplete snapshot unknown');
tc(QueueCohort::capture($now,1)['complete']===false,'Count mismatch unknown');
$reads=\WHMCS\Database\Capsule::$reads;tc(!QueueCohort::capture($now,QueueCohort::LIMIT+1)['complete']&&\WHMCS\Database\Capsule::$reads===$reads,'Limit does not read unbounded rows');
$due=row('due',['processing_state'=>'retry','retry_at'=>date('Y-m-d H:i:s',$now),'last_event_at'=>date('Y-m-d H:i:s',$now)]);
\WHMCS\Database\Capsule::$rows=[$due];tc(QueueCohort::capture($now,1)['complete'],'Due retry included');
$memory=row('memory',['last_event_at'=>date('Y-m-d H:i:s',$now),'bucket'=>date('Y-m-d H:i:s',$now-86400)]);
$m=QueueCohort::fromRows([$memory],$now,1800,86400,1);tc(QueueCohort::crossed($m,$now+1)===true,'Memory boundary counted');
foreach([['id'=>'bad'],['revision'=>0],['revision'=>'wrong'],['last_event_at'=>'wrong'],['bucket'=>'wrong'],['analyzed_revision'=>2]] as $bad)
 tc(!QueueCohort::fromRows([array_replace($ready,$bad)],$now,1800,86400,1)['complete'],'Malformed metadata never complete');
tc(!QueueCohort::fromRows([$ready,$ready],$now,1800,86400,2)['complete'],'Duplicate identity refused');
tc(!QueueCohort::fromRows([$ready],$now,0,86400,1)['complete'],'Invalid duration refused');
\WHMCS\Database\Capsule::$fail=true;try{QueueCohort::capture($now,1);tc(false,'Must signal read failure');}catch(\RuntimeException $e){tc(true,'Read failure reaches observational guard');}finally{\WHMCS\Database\Capsule::$fail=false;}
$rows=[['eligible_ready_start'=>0,'eligible_ready_end'=>0],['eligible_ready_start'=>0,'eligible_ready_end'=>0]];
$health=['ready'=>0,'backoff'=>0,'awaiting_recheck'=>0];
tc(QueueTelemetry::capacity($rows,$health,0,0,0)['capacity']==='idle','Idle is not insufficient capacity');
tc(QueueTelemetry::capacity($rows,$health,2,2,0)['capacity']==='caught_up','Demand handled, now current');
tc(QueueTelemetry::capacity($rows,$health,0,0,1)['capacity']==='inconclusive_expiry','Expiration cannot masquerade as idle');
tc(QueueTelemetry::capacity($rows,['ready'=>0,'backoff'=>2],0,0,0)['capacity']==='waiting_retry','Delayed work not called current');
$flat=[['eligible_ready_start'=>3,'eligible_ready_end'=>3],['eligible_ready_start'=>3,'eligible_ready_end'=>3]];
tc(QueueTelemetry::capacity($flat,['ready'=>3],5,5,0)['capacity']==='stable','Stable demand is not proven capacity deficit');
tc(QueueTelemetry::capacity($flat,['ready'=>3],0,0,0)['capacity']==='stable','No progress called stable, not draining');
$drain=[['eligible_ready_start'=>5,'eligible_ready_end'=>3],['eligible_ready_start'=>3,'eligible_ready_end'=>1]];
$d=QueueTelemetry::capacity($drain,['ready'=>4],2,6,0);tc($d['capacity']==='draining'&&$d['estimated_cycles']===2,'Measured drain estimate');
tc(QueueTelemetry::capacity($drain,['ready'=>4,'backoff'=>2],2,6,0)['estimated_cycles']===null,'Backoff not forecast as immediately ready');
$growth=[['eligible_ready_start'=>1,'eligible_ready_end'=>3],['eligible_ready_start'=>3,'eligible_ready_end'=>5]];
tc(QueueTelemetry::capacity($growth,['ready'=>5],8,4,0)['capacity']==='insufficient_capacity','Actual comparable growth identified');
tc(QueueTelemetry::capacity($growth,$health,8,4,0)['capacity']==='caught_up','Current empty queue distinguished from historical growth');
tc(QueueTelemetry::capacity([], $health,0,0,0)['capacity']==='insufficient_data','Not enough intervals never called healthy');
tc(QueueTelemetry::capacity($rows,[],0,0,0)['capacity']==='insufficient_data','Unknown ready count not zero');
$base=['started_at'=>$now-60,'finished_at'=>$now,'error'=>'','reason'=>'queue_not_ready','completed'=>0,'local_observed'=>0,'eligible_ready_start'=>0,'eligible_ready_end'=>0,'eligible_comparable'=>true,'eligibility_policy_hash'=>'cohort-fixture'];
$legacy=$base+['metric_version'=>2,'entries_total'=>10,'expired_total'=>3,'entries_since_previous'=>5,'expired_since_previous'=>0];
Database::$cfg+=['ai_cycle_metrics'=>json_encode([$legacy]),'ai_queue_entries_total'=>'10','ai_queue_expired_total'=>'3'];
QueueTelemetry::finish($base);$h=QueueTelemetry::history();$last=end($h);
tc(count($h)===2&&$h[0]===$legacy,'Old metric history retained');
tc($last['metric_version']===3&&$last['entries_since_previous']===null,'No mixed v2-v3 interval');
tc(Database::$cfg['ai_queue_entries_total']==='10','Counter preserved');
tc(QueueTelemetry::summary($health)['capacity']==='insufficient_data','First corrected cycle not enough');
QueueTelemetry::finish($base);QueueTelemetry::finish($base);$s=QueueTelemetry::summary($health);
tc($s['capacity']==='idle'&&$s['estimated_cycles']===0,'Real summary idle regression');
tc(QueueTelemetry::summary(['ready'=>0,'awaiting_recheck'=>1])['capacity']==='awaiting_recheck','Unknown coverage precedence');
$invalid=$base;$invalid['eligible_comparable']=false;QueueTelemetry::finish($invalid);
tc(QueueTelemetry::summary($health)['capacity']==='insufficient_data','Incomparable cycle breaks trend');
$engine=file_get_contents(dirname(__DIR__).'/lib/AutoBanEngine.php');
tc(strpos($engine,'QueueCohort::capture')<strpos($engine,'while($calls<Policy::number'), 'Snapshot precedes worker selection');
tc(str_contains($engine,"catch(\\Throwable \$ignored){\$metrics['measurement_error']='cohort_unavailable';}"),'Capture failure stays observational');
tc(!str_contains($engine,'RecentActivity::crossedCutoff'),'Global history expiry query retired');
$tpl=file_get_contents(dirname(__DIR__).'/templates/protection_diagnostics.tpl');
foreach(['idle','caught_up','waiting_retry','stable','inconclusive_expiry'] as $state)tc(str_contains($tpl,"'".$state."'=>"),'UI state mapped');
echo "PASS: {$n} cohort identity/expiry, query, capacity and v3 history checks; memory-only\n";
}
