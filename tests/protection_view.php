<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $config=[];public static function getConfig($key,$default=''){return self::$config[$key]??$default;}}
class DecisionMemory {public static int $calls=0;public static string $hash='current';public static function policyFingerprint(){self::$calls++;return self::$hash;}}
require dirname(__DIR__).'/lib/QueueExpiry.php';
require dirname(__DIR__).'/lib/ProtectionView.php';
require dirname(__DIR__).'/lib/QueueTelemetry.php';
require dirname(__DIR__).'/lib/BehaviorStore.php';
require dirname(__DIR__).'/lib/Router.php';
$n=0;function check($value,$message){global $n;if(!$value)throw new \RuntimeException($message);$n++;}
$now=1700000000;
Database::$config=['schema_version'=>'31'];
$expiry=QueueExpiry::describe(date('Y-m-d H:i:s',$now-901),30,15,$now);
check($expiry['warning']&&$expiry['seconds_remaining']===899,'Warning precedes 30-minute expiry with 60-minute legacy age alert');
check(!QueueExpiry::describe(date('Y-m-d H:i:s',$now-60),30,15,$now)['warning'],'Fresh task is not urgent');
check(!QueueExpiry::describe(null,30,15,$now)['warning'],'Empty, protected or historical-only queue has no expiry warning');
check(QueueExpiry::describe(date('Y-m-d H:i:s',$now-1800),30,15,$now)['seconds_remaining']===0,'Expiry never becomes completion or negative time');
check(QueueExpiry::describe(date('Y-m-d H:i:s',$now),5,15,$now)['warning_margin_seconds']===299,'Margin stays inside window when interval too large');
check(!QueueExpiry::describe('not a timestamp',30,15,$now)['warning'],'Unknown timestamp is not manufactured');
$values=['ai_stale_minutes'=>45,'ai_cycle_seconds'=>180,'ai_auto_enabled'=>'1'];
$health=['collector'=>$now,'cycle'=>$now,'error'=>'','queue'=>['ready'=>0],'jail'=>['success'=>true],'telemetry'=>['state'=>['status'=>'completed']]];
check(ProtectionView::states($values,$health,$now,$now)['ai']['tone']==='success','Idle fresh cycle does not require paid API');
$bad=$health;$bad['cycle']=$now-86400;
check(ProtectionView::states($values,$bad,$now,$now)['ai']['tone']==='warning','Fresh collector cannot mask old cycle');
$bad['error']='provider failure';
check(ProtectionView::states($values,$bad,$now,$now)['ai']['tone']==='danger','Provider error highlighted separately');
$off=$values;$off['ai_auto_enabled']='0';
check(ProtectionView::states($off,$bad,$now,$now)['ai']['label']==='Desativada','Disabled operation explicitly shown');
$running=$health;$running['telemetry']['state']=['status'=>'running','started_at'=>$now-10];
check(ProtectionView::states($values,$running,$now,$now)['ai']['label']==='Em análise','Live running cycle');
$running['telemetry']['state']['started_at']=$now-1000;
check(ProtectionView::states($values,$running,$now,$now)['ai']['tone']==='warning','Hung running cycle warned');
$bad=$health;$bad['collector_error']='collector failure';
check(ProtectionView::states($values,$bad,$now,$now)['collector']['tone']==='warning','Fresh timestamp does not suppress collector error');
$bad=$health;$bad['queue']['age_alert']=true;
check(ProtectionView::states($values,$bad,$now,$now)['queue']['tone']==='warning','Expiry/age warning has own card');
$bad=$health;$bad['queue']=['ready'=>0,'age_alert'=>false,'expiry'=>['warning'=>true]];
check(ProtectionView::states($values,$bad,$now,$now)['queue']['label']==='Atenção ao prazo','Expiry independent of legacy age warning');
foreach([null,-1,'bad',[],true] as $unknown){
 $bad=$health;$bad['queue']=['ready'=>$unknown];
 check(ProtectionView::states($values,$bad,$now,$now)['queue']['label']==='Fila não medida','Unknown ready is not an empty queue');
}
$bad=$health;unset($bad['queue']);check(ProtectionView::states($values,$bad,$now,$now)['queue']['tone']==='warning','Absent queue warns');
check(ProtectionView::states($values,$health,$now,$now)['queue']['label']==='Sem trabalho pronto','Measured zero preserved');
check(!BehaviorStore::requeueEligibility(['processing_state'=>'review','bucket'=>date('Y-m-d H:i:s',$now-90000)],$now,24)['allowed'],'Historical review cannot be requeued');
$line='198.51.100.77 - - ['.date('d/M/Y:H:i:s O',$now-100).'] "GET /.env HTTP/1.1" 404 100 "-" "fixture"';
$review=['ip'=>'198.51.100.77','processing_state'=>'review','bucket'=>date('Y-m-d H:i:s',$now-100),'last_event_at'=>date('Y-m-d H:i:s',$now-100),'samples'=>json_encode([['line'=>$line]])];
check(BehaviorStore::requeueEligibility($review,$now,24)['allowed'],'Current review with individual proof is actionable');
$cold=$review;$cold['last_event_at']=date('Y-m-d H:i:s',$now-3600);
check(!BehaviorStore::requeueEligibility($cold,$now,24)['allowed'],'Cold metadata is not promised paid reanalysis');
$cold=$review;$cold['samples']='[]';
check(!BehaviorStore::requeueEligibility($cold,$now,24)['allowed'],'Missing proof cannot authorize requeue');
$cold=$review;$cold['samples']=json_encode([['line'=>str_replace('198.51.100.77','198.51.100.78',$line)]]);
check(!BehaviorStore::requeueEligibility($cold,$now,24)['allowed'],'Other peer proof cannot authorize requeue');
$cold=$review;$cold['samples']=json_encode([['line'=>str_replace(date('d/M/Y:H:i:s O',$now-100),date('d/M/Y:H:i:s O',$now-3600),$line)]]);
check(!BehaviorStore::requeueEligibility($cold,$now,24)['allowed'],'Fresh metadata cannot revive old proof');
foreach([null,0,-1,'bad',(string)($now+1),$now+86400] as $invalid){
    $bad=$health;$bad['cycle']=$invalid;
    check(ProtectionView::states($values,$bad,0,$now)['ai']['tone']==='warning','Invalid/future heartbeat cannot appear healthy');
    $bad=$health;$bad['telemetry']['state']=['status'=>'running','started_at'=>$invalid];
    check(ProtectionView::states($values,$bad,$now,$now)['ai']['tone']==='warning','Invalid/future start cannot appear running');
}
foreach([null,-1,'bad',[],true,'1junk',1.5] as $unknown)check(ProtectionView::count($unknown)==='não medido','Unknown or malformed count is not zero');
foreach([0,'0',17,'17'] as $known)check(ProtectionView::count($known)===(string)$known,'Measured count preserved including zero');
check(!BehaviorStore::requeueEligibility(['processing_state'=>'pending','bucket'=>date('Y-m-d H:i:s',$now)],$now,24)['allowed'],'Non-review not actionable');
check(!BehaviorStore::requeueEligibility(['processing_state'=>'review','bucket'=>'bad'],$now,24)['allowed'],'Unparseable bucket fails closed');
Database::$config['schema_version']='31';$cycles=[];
for($i=0;$i<200;$i++)$cycles[]=['eligibility_policy_hash'=>'current','error'=>'','reason'=>'queue_not_ready','finished_at'=>time()-200+$i,'entries_since_previous'=>2,'expired_since_previous'=>0,'completed'=>3,'eligible_comparable'=>true,'eligible_ready_start'=>3,'eligible_ready_end'=>2];
Database::$config['ai_cycle_metrics']=json_encode($cycles);
$summary=QueueTelemetry::summary(['ready'=>2]);
check(DecisionMemory::$calls===1&&$summary['cycles']===6,'Two hundred cycles require one policy fingerprint, not 200');
DecisionMemory::$hash='changed';QueueTelemetry::summary(['ready'=>2]);
check(DecisionMemory::$calls===2,'Next summary re-reads changed policy instead of global caching');
check(QueueTelemetry::summary(['ready'=>2])['cycles']===0,'Policy mismatch cannot reuse old capacity');
foreach(['filter_positive','filter_branch','update_cooldown','time_limit'] as $code)check(ProtectionView::code($code)!==$code,'Known internal code translated');
echo "PASS: {$n} pure protection state/expiry/review/fingerprint checks; no SQL/provider/native\n";
