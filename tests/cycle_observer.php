<?php
// Memory-only fixtures: no WHMCS bootstrap, database, native commands or API.
require dirname(__DIR__).'/lib/CycleObserver.php';
use AMS\Fail2Ban\CycleObserver;

$checks=0;
function check(bool $condition,string $message): void {
    global $checks;
    if(!$condition)throw new RuntimeException($message);
    $checks++;
}
function cycle(int $finish,array $changes=[]): array {
    return array_replace(['started_at'=>$finish-5,'finished_at'=>$finish,'duration_seconds'=>5.0,
        'generation'=>'fixture-generation','error'=>'','reason'=>'queue_not_ready','calls'=>1,
        'retry_calls'=>0,'retry_calls_with_fresh_work'=>0,'selected'=>1,'completed'=>1,
        'refused'=>0,'review'=>0,'recovered'=>0],$changes);
}
function coverage(array $changes=[]): array {
    return ['success'=>true,'snapshot'=>array_replace(['timestamp'=>'fixture-time','coverage_version'=>4,
        'active_jails'=>3,'missing_jail_tickets'=>0,'missing_f2b_rules'=>0,'orphan_firewall_ips'=>0,
        'duplicate_prefix_jails'=>0,'jails_without_actions'=>[],'jails_unverified'=>[],
        'jail_coverage'=>['large detail'],'scope'=>'fixture native scope'],$changes)];
}
$limits=['calls'=>10,'seconds'=>180,'retry_percent'=>30];
function observe(callable $history,?callable $snapshot=null,array $options=[],?callable $waitHook=null): array {
    global $limits;
    $time=0.0;$events=[];$waits=[];$reads=0;
    $code=CycleObserver::watch($options+['seconds'=>60,'cycles'=>2],$limits,'fixture-generation',
        function()use(&$time,&$reads,$history){return $history($time,$reads++);},
        function()use(&$time,$snapshot){return $snapshot?$snapshot($time):coverage();},
        function($event)use(&$events){$events[]=$event;},
        function()use(&$time){return $time;},function()use(&$time){return 1000+(int)$time;},
        function($seconds)use(&$time,&$waits,$waitHook){$waits[]=$seconds;$time+=$seconds;if($waitHook)$waitHook($time);});
    return ['code'=>$code,'events'=>$events,'last'=>end($events),'time'=>$time,'waits'=>$waits,'reads'=>$reads];
}

check(CycleObserver::options([])===['seconds'=>3600,'cycles'=>2],'CLI defaults');
check(CycleObserver::options(['--seconds=60','--cycles','1'])===['seconds'=>60,'cycles'=>1],'CLI minimum and both syntaxes');
check(CycleObserver::options(['--seconds','86400','--cycles=10'])===['seconds'=>86400,'cycles'=>10],'CLI maximum');
foreach([['--seconds','59'],['--seconds=86401'],['--cycles=0'],['--cycles=11'],['--seconds'],
    ['--seconds='],['--seconds=1e3'],['--seconds=60.0'],['--seconds=-60'],['--seconds=INF'],
    ['--cycles=2','--cycles=2'],['--unknown=1'],['60'],['--cycles','--seconds=60']] as $args) {
    try{CycleObserver::options($args);check(false,'Invalid CLI accepted');}catch(InvalidArgumentException $e){check(true,'Invalid CLI refused');}
}
check(CycleObserver::history('[]')===[],'Empty persisted history');
foreach(['null','{"x":1}','[null]','bad json'] as $json) {
    try{CycleObserver::history($json);check(false,'Malformed history accepted');}
    catch(JsonException|UnexpectedValueException $e){check(true,'Malformed history refused');}
}
check(CycleObserver::metricsValid(cycle(1010),$limits,'fixture-generation'),'Measured cycle valid');
foreach([['calls'=>'1'],['selected'=>-1],['duration_seconds'=>INF],['duration_seconds'=>NAN],
    ['generation'=>'old'],['error'=>'provider_error'],['finished_at'=>900],['retry_calls'=>2],
    ['retry_calls_with_fresh_work'=>1],['completed'=>2],['duration_seconds'=>181],['duration_seconds'=>8.1]] as $changes) {
    check(!CycleObserver::metricsValid(cycle(1010,$changes),$limits,'fixture-generation'),'Operational gate: '.key($changes));
}
$bad=cycle(1010);unset($bad['recovered']);
check(!CycleObserver::metricsValid($bad,$limits,'fixture-generation'),'Missing counter refused');
$blocked=cycle(1010,['calls'=>0,'selected'=>0,'completed'=>0,'reason'=>'all_candidates_blocked',
    'blocked'=>['confirmed'=>true,'held'=>2]]);
check(CycleObserver::metricsValid($blocked,$limits,'fixture-generation'),'Explicit protected zero-call cycle accepted');
$blocked['blocked']['confirmed']=false;
check(!CycleObserver::metricsValid($blocked,$limits,'fixture-generation'),'Unknown blocked coverage cannot qualify');
check(!CycleObserver::metricsValid(cycle(1010,['calls'=>0,'selected'=>0,'completed'=>0]),$limits,'fixture-generation'),'Idle zero-call cycle incomplete');
$local=cycle(1010,['calls'=>0,'selected'=>0,'completed'=>0,'reason'=>'local_work_completed','reused'=>1,'resumed'=>0]);
foreach([['reused'=>1,'resumed'=>0],['reused'=>0,'resumed'=>1],['reused'=>2,'resumed'=>3]] as $changes)
    check(CycleObserver::metricsValid(array_replace($local,$changes),$limits,'fixture-generation'),'Measured local work accepted without API');
foreach([['reused'=>0,'resumed'=>0],['reused'=>-1],['resumed'=>-1],['reused'=>'1'],['resumed'=>0.0],
    ['selected'=>1],['completed'=>1],['retry_calls'=>1],['retry_calls_with_fresh_work'=>1],['error'=>'worker_error'],
    ['reason'=>'queue_not_ready'],['duration_seconds'=>181],['generation'=>'old']] as $changes)
    check(!CycleObserver::metricsValid(array_replace($local,$changes),$limits,'fixture-generation'),'Invalid local work refused: '.key($changes));
foreach(['reused','resumed'] as $key) {
    $missingLocal=$local;unset($missingLocal[$key]);
    check(!CycleObserver::metricsValid($missingLocal,$limits,'fixture-generation'),'Missing local counter refused: '.$key);
}
$retiredLocal=array_replace($local,['reused'=>0,'resumed'=>0,'local_observed'=>1]);
check(CycleObserver::metricsValid($retiredLocal,$limits,'fixture-generation'),'Retired local observation accepted without API');
foreach([-1,'1',1.0,0] as $badLocal)check(!CycleObserver::metricsValid(array_replace($retiredLocal,['local_observed'=>$badLocal]),$limits,'fixture-generation'),'Invalid retired local counter accepted');
check(CycleObserver::protection(coverage())==='ok','Current coverage healthy');
check(CycleObserver::protection(['success'=>false])==='unknown','Unavailable snapshot is not protection failure');
check(CycleObserver::protection(coverage(['coverage_version'=>3]))==='unknown','Unsupported version is unknown');
check(CycleObserver::protection(coverage(['jails_unverified'=>['fixture']]))==='unknown','Unverified actions are unknown');
foreach(['active_jails'=>0,'missing_jail_tickets'=>1,'missing_f2b_rules'=>1,'orphan_firewall_ips'=>1,
    'duplicate_prefix_jails'=>1,'jails_without_actions'=>['fixture']] as $key=>$value)
    check(CycleObserver::protection(coverage([$key=>$value]))==='failed','Measured protection failure: '.$key);
$missing=coverage();unset($missing['snapshot']['missing_f2b_rules']);
check(CycleObserver::protection($missing)==='unknown','Missing coverage counter is unknown');
check(CycleObserver::protection(coverage(['missing_f2b_rules'=>'0']))==='unknown','Untyped coverage is unknown');

// Two rows appear between polls; latest heartbeat/state/counters play no role.
$result=observe(fn($t)=>$t>=30?[cycle(1020),cycle(1010),cycle(990)]:[cycle(990)]);
check($result['code']===0&&$result['last']['accepted']===2,'Enumerates all new persisted cycles');
$observed=array_values(array_filter($result['events'],fn($e)=>$e['status']==='cycle_observed'));
check(array_column($observed,'cycle_id')===['1005:1010','1015:1020'],'History ordered and baseline excluded');
check(!array_key_exists('coverage',$observed[0])&&!$observed[0]['historical_coverage_attested'],'Historical cycle never claims current coverage');
$snapshots=array_values(array_filter($result['events'],fn($e)=>$e['status']==='protection_snapshot'));
check($snapshots[1]['scope']==='current_protection_only'&&$snapshots[1]['snapshot_started_at']===1030
    &&$snapshots[1]['snapshot_finished_at']===1030,'Current snapshot explicitly scoped and timestamped');
check(!isset($snapshots[1]['coverage']['jail_coverage'])&&$snapshots[1]['coverage']['scope']==='fixture native scope','Compact snapshot preserves native scope');

$result=observe(fn($t)=>$t>=60?[cycle(1010),cycle(1060)]:($t>=30?[cycle(1010)]:[]));
check($result['code']===0&&$result['time']===60.0,'Final poll includes deadline completion');
check($result['last']['observed']===2,'Repeated history not counted twice');
$result=observe(fn()=>[]);
check($result['code']===3&&$result['last']['reason']==='insufficient_cycles'&&$result['reads']===4,'No cycles: baseline plus initial, intermediate and final polls');
check($result['waits']===[30.0,30.0],'No sleep past deadline');
$result=observe(fn($t)=>$t>=60?[cycle(1060),cycle(1061)]:[]);
check($result['code']===3&&$result['last']['observed']===1,'After-deadline row excluded');
$result=observe(fn()=>[cycle(1000),cycle(990)]);
check($result['code']===3&&$result['last']['observed']===0,'Startup-second baseline cannot count');
$result=observe(fn($t)=>$t>=30?[cycle(1010),cycle(1010)]:[]);
check($result['code']===3&&$result['last']['observed']===1,'Duplicate history row counted once');
$result=observe(fn($t)=>$t>=30?[cycle(1010,['error'=>'provider_error']),cycle(1020)]:[]);
check($result['code']===3&&$result['last']['current_protection']==='ok'
    &&$result['last']['reason']==='cycle_metrics_rejected','Cycle error is operational incomplete, not protection failure');
$result=observe(fn($t)=>$t>=30?[cycle(1010),cycle(1020)]:[],fn()=>['success'=>false]);
check($result['code']===3&&$result['last']['reason']==='coverage_unavailable','Good metrics cannot attest unavailable coverage');
$result=observe(fn()=>[],fn()=>coverage(['missing_f2b_rules'=>1]));
check($result['code']===2&&$result['last']['kind']==='current_protection','Protection failure distinguished even without cycles');
$result=observe(fn()=>[],function(){throw new RuntimeException('fixture');});
check($result['code']===3&&$result['last']['current_protection']==='unknown','Snapshot exception incomplete');
$result=observe(function($t,$read){if($read>0)throw new RuntimeException('fixture');return [];});
check($result['code']===3&&$result['last']['reason']==='history_unavailable','History exception incomplete');
$result=observe(fn($t)=>$t>=30?[cycle(1010)]:[],null,['cycles'=>1]);
check($result['code']===0&&$result['time']===30.0,'Configured cycle target honored');
$result=observe(fn()=>[],null,['seconds'=>61]);
check($result['time']===61.0&&end($result['waits'])===1.0,'Fractional final interval bounded by remaining time');
$result=observe(fn($t)=>$t>=60?[cycle(1060)]:[],null,['cycles'=>1],function(&$time){$time+=5;});
check($result['code']===0&&$result['time']===65.0,'Late wake still performs final poll for in-window cycle');
$result=observe(fn($t)=>$t>=60?[cycle(1060)]:($t>=30?[cycle(1010)]:[]));
check($result['code']===0&&$result['last']['observed']===2,'Seen cycles survive persisted history rotation');
$result=observe(function($t,$read){if($read===1)throw new RuntimeException('transient');return $t>=30?[cycle(1010),cycle(1020)]:[];});
check($result['code']===0,'Transient history read failure can recover');
$result=observe(fn($t)=>$t>=30?[cycle(1010),cycle(1020)]:[],fn($t)=>$t>=60?coverage():['success'=>false]);
check($result['code']===0&&$result['time']===60.0,'Current coverage must recover before success');
$blocked=cycle(1010,['calls'=>0,'selected'=>0,'completed'=>0,'reason'=>'all_candidates_blocked',
    'blocked'=>['confirmed'=>true,'held'=>2]]);
$result=observe(fn($t)=>$t>=30?[$blocked]:[],null,['cycles'=>1]);
check($result['code']===0,'No API calls needed for explicitly protected cycle');
$result=observe(fn($t)=>$t>=30?array_map(fn($n)=>cycle(1000+$n),range(1,10)):[],null,['cycles'=>10]);
check($result['code']===0&&$result['last']['accepted']===10,'Maximum cycle target honored');
$result=observe(fn($t)=>$t>=30?[$local]:[],null,['cycles'=>1]);
check($result['code']===0&&$result['last']['accepted']===1,'Local work completes observer with current coverage');
$result=observe(fn($t)=>$t>=30?[$local]:[],fn()=>['success'=>false],['cycles'=>1]);
check($result['code']===3&&$result['last']['reason']==='coverage_unavailable','Local work still requires measured current coverage');
echo "PASS: {$checks} pure cycle observer checks; no DB/API/native calls\n";
