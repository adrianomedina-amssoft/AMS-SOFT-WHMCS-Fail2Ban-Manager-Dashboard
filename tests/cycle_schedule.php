<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__).'/lib/CycleSchedule.php';
$n=0;function sched($v,$why){global $n;if(!$v)throw new \RuntimeException($why);$n++;}
$now=100000;$start=$now-300;$finish=$start+120;
sched(CycleSchedule::decision($now,$start,$finish,900)==='waiting','Regular interval not honored');
sched(CycleSchedule::decision($start+900,$start,$finish,900)==='interval','Interval wrongly anchored to finish');
sched(CycleSchedule::decision($now,0,$now-900,900)==='interval','Legacy fallback missing');
sched(CycleSchedule::decision($now,0,0,900)==='interval','First cycle missing');
sched(CycleSchedule::decision($now,$now+1,0,900)==='clock_unknown','Future start accepted');
sched(CycleSchedule::decision($now,0,$now+1,900)==='clock_unknown','Future finish accepted');
// Real case: request12:40:38, first refusal13:00:42, retry13:02:42,
// regular next would be13:15+cron; next4minute tick still precedes13:10:38expiry.
$event=100000;$cycle=$event+1168;$refused=$event+1204;$retry=$refused+120;$tick=$event+1408;
sched(CycleSchedule::decision($tick,$cycle,$cycle+117,900,$retry,$event)==='retry_deadline','Real expired-retry gap persists');
foreach([['early'=>false],['retry'=>$tick+1],['event'=>$tick-1800],['event'=>$tick+1],['minimum'=>300]] as $case){$args=[$tick,$cycle,$cycle+117,900,$case['retry']??$retry,$case['event']??$event,1800,$case['early']??true,180,$case['minimum']??120];sched(CycleSchedule::decision(...$args)==='waiting','Invalid early cycle accepted');}
sched(CycleSchedule::decision($now,$start,$finish,900,$now-1,$now-1)==='waiting','Young retry forced needless cycle');
sched(CycleSchedule::decision($now,$start,$finish,900,0,$now-1700)==='waiting','No ready retry authorized cycle');
sched(CycleSchedule::retryFirst('retry_deadline',0,3),'Early cycle did not reserve first eligible call for retry');
sched(!CycleSchedule::retryFirst('interval',0,3)&&!CycleSchedule::retryFirst('retry_deadline',1,3)&&!CycleSchedule::retryFirst('retry_deadline',0,0),'Retry priority bypassed quota or regular fairness');
echo "PASS: {$n} pure deadline schedule/backoff/clock/configuration checks; no SQL/provider\n";
