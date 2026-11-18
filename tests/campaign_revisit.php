<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static function getConfig($k,$d=''){return $k==='schema_version'?'37':$d;}}
class Policy {public static function number($k){return ['ai_analysis_recent_minutes'=>30][$k];}}
require dirname(__DIR__).'/lib/Router.php';
$n=0;function revisitCheck($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
$now=time();
function revisitFixture($age,$now):array{
 $line='198.51.100.77 - - ['.date('d/M/Y:H:i:s O',$now-$age).'] "GET /boaform/adminformLogout//boaform/admin/login.asp HTTP/1.0" 404 10 "-" "-"';
 return ['id'=>hash('sha256','row'.$age),'ip'=>'198.51.100.77','source_log'=>'/var/log/apache2/access.log','pattern'=>BehaviorStore::pattern($line),'revision'=>1,'analyzed_revision'=>1,'processing_state'=>'processed','last_event_at'=>date('Y-m-d H:i:s',$now-$age),'samples'=>json_encode([['line'=>$line,'time'=>$now-$age]])];
}
$fresh=revisitFixture(60,$now);$old=revisitFixture(51685,$now);
revisitCheck(BehaviorStore::revisitEligible($fresh,$now),'Fresh same-IP bucket remains eligible');
revisitCheck(!BehaviorStore::revisitEligible($old,$now),'14h-old bucket cannot reopen beside newer bucket of same IP/pattern');
revisitCheck(BehaviorStore::revisitEligible(revisitFixture(1800,$now),$now),'Inclusive recent boundary');
revisitCheck(!BehaviorStore::revisitEligible(revisitFixture(1801,$now),$now),'Outside boundary');
foreach(['review','rejected'] as $state)revisitCheck(!BehaviorStore::revisitEligible(array_replace($fresh,['processing_state'=>$state]),$now),'Protected workflow '.$state);
foreach([
 ['revision'=>0],['analyzed_revision'=>0],['analyzed_revision'=>2],['decision_state'=>'rejected'],
 ['retry_at'=>date('c',$now+1)],['retry_at'=>'not-a-date'],['blocked_confirmed_at'=>date('c',$now-60)],
 ['blocked_until_check_at'=>date('c',$now+1)],['last_event_at'=>date('c',$now-1801)],['last_event_at'=>date('c',$now+301)],
 ['samples'=>'[]'],['samples'=>'invalid'],['ip'=>'198.51.100.78'],['samples'=>$old['samples']],
] as $change)revisitCheck(!BehaviorStore::revisitEligible(array_replace($fresh,$change),$now),'Unsafe or stale subject rejected: '.implode(',',array_keys($change)));
revisitCheck(BehaviorStore::revisitEligible(array_replace($fresh,['attempts'=>2,'validation_attempts'=>2,'retry_at'=>date('c',$now-1)]),$now),'Due previous retry budget is not reset or rejected');
$wrong=revisitFixture(-301,$now);revisitCheck(!BehaviorStore::revisitEligible($wrong,$now),'Future evidence refused');
echo "PASS: {$n} campaign revisit freshness, task-state, peer, held/backoff and 14h bucket checks; no SQL/native/provider\n";
