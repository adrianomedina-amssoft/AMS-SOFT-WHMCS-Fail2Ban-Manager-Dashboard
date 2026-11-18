<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=['schema_version'=>'37','ai_coverage_recheck_enabled'=>'1'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}}
require dirname(__DIR__).'/lib/Router.php';
$n=0;function recoveryCheck($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
$now=time();$ip='198.51.100.77';
$line=$ip.' - - ['.date('d/M/Y:H:i:s O',$now-10).'] "GET / HTTP/1.1" 400 10 "-" "fixture"';
$row=['ip'=>$ip,'source_log'=>'/var/log/apache2/access_whmcs.log','revision'=>2,'analyzed_revision'=>1,
    'processing_state'=>'pending','failure_code'=>'coverage_unavailable','attempts'=>0,'samples'=>json_encode([['line'=>$line]])];
$snapshot=['success'=>true,'stable'=>true,'errors'=>[],'observed_at'=>$now,'ttl'=>300,'requirements'=>['http'=>[80,443]],'entries'=>[]];
recoveryCheck(BlockedTasks::recoverable($row,$snapshot),'Known unprotected local coverage should release deferral');
foreach([['processing_state'=>'retry'],['processing_state'=>'review'],['attempts'=>1],['analyzed_revision'=>2],
         ['decision_state'=>'rejected'],['failure_code'=>'filter_positive'],['samples'=>'[]']] as $bad)
    recoveryCheck(!BlockedTasks::recoverable(array_replace($row,$bad),$snapshot),'Unrelated work must remain untouched');
foreach([['success'=>false],['stable'=>false],['errors'=>['unavailable']],['observed_at'=>$now-301],['observed_at'=>$now+10]] as $bad)
    recoveryCheck(!BlockedTasks::recoverable($row,array_replace($snapshot,$bad)),'Unknown protection must not release work');
$protected=$snapshot;$protected['entries']=[['ip'=>$ip,'effective'=>true,'protocol'=>'tcp','expires_at'=>$now+1000,'ports'=>[80,443],'jail'=>'fixture','ticket'=>'fixture']];
recoveryCheck(!BlockedTasks::recoverable($row,$protected),'Protected IP remains held');
Database::$cfg['ai_coverage_recheck_enabled']='0';
recoveryCheck(!BlockedTasks::recoverable($row,$snapshot),'Opt-out must work');
Database::$cfg['ai_coverage_recheck_enabled']='1';
$cold=$row;$cold['samples']=json_encode([['line'=>str_replace(date('d/M/Y:H:i:s O',$now-10),date('d/M/Y:H:i:s O',$now-1900),$line)]]);
recoveryCheck(!BlockedTasks::recoverable($cold,$snapshot),'Cold evidence must not reopen');
recoveryCheck(QueueExpiry::category(['blocked_confirmed_at'=>date('c',$now-5),'blocked_until_check_at'=>date('c',$now+5)],$now)==='protected','Live protection expiry reason');
recoveryCheck(QueueExpiry::category(['blocked_confirmed_at'=>date('c',$now-5),'blocked_until_check_at'=>date('c',$now)],$now)==='unclassified','Expired proof cannot claim protection');
recoveryCheck(QueueExpiry::category(['blocked_confirmed_at'=>date('c',$now+5),'blocked_until_check_at'=>date('c',$now+10)],$now)==='unclassified','Future proof refused');
recoveryCheck(QueueExpiry::category(['failure_code'=>'coverage_unavailable'],$now)==='coverage_unavailable','Local failure reason');
recoveryCheck(QueueExpiry::category(['failure_code'=>'filter_positive'],$now)==='unclassified','Do not mislabel validation');
recoveryCheck(QueueTelemetry::expiryBreakdown([['expired_since_previous'=>2,'expiry_since_previous'=>['protected'=>1,'coverage_unavailable'=>1,'unclassified'=>0]]])===['protected'=>1,'coverage_unavailable'=>1,'unclassified'=>0],'Complete breakdown preserved');
foreach([[],[['expired_since_previous'=>2]], [['expired_since_previous'=>2,'expiry_since_previous'=>['protected'=>1,'coverage_unavailable'=>0,'unclassified'=>0]]],
    [['expired_since_previous'=>0,'expiry_since_previous'=>['protected'=>-1,'coverage_unavailable'=>1,'unclassified'=>0]]]] as $bad)
    recoveryCheck(QueueTelemetry::expiryBreakdown($bad)===null,'Unknown/mismatched/negative interval must remain unknown');
echo "PASS: {$n} coverage recovery, refusal and expiry reason checks; no SQL/provider/native\n";
