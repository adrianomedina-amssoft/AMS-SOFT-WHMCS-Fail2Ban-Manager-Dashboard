<?php
if(PHP_SAPI!=='cli')exit(1);
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule;
use AMS\Fail2Ban\{Database,BehaviorStore,AIAnalyzer,AutoBanEngine,QueueTelemetry,Migrations,Policy};
$c=new Capsule();$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
$db=Capsule::connection();$checks=0;
function check($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy; retry');
$db->beginTransaction();$path=tempnam('/var/log','amsfb-recovery-');
$cache=new ReflectionProperty(AutoBanEngine::class,'cycleValidationCache');$cache->setAccessible(true);
try {
    Migrations::run();Migrations::run(); // Never persist fixture migration settings.
    Database::setConfig('schema_version','23'); // Legacy recovery/capacity fixtures; schema25 admission has dedicated tests.
    Capsule::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>Capsule::raw('revision')]);
    foreach(['ai_whitelist_ips'=>'','ai_review_auto_recovery_enabled'=>'1','ai_review_recovery_limit'=>'1','ai_cycle_metrics'=>'[]','ai_queue_entries_total'=>'0','ai_queue_expired_total'=>'0'] as $k=>$v)Database::setConfig($k,$v);
    $line='198.51.100.245 - - ['.date('d/M/Y:H:i:s O').'] "GET /.env HTTP/1.1" 404 100 "-" "scanner"';
    file_put_contents($path,$line."\n");BehaviorStore::collect($path);file_put_contents($path,$line."\n",FILE_APPEND);BehaviorStore::collect($path);
    $row=fn()=>(array)Capsule::table('mod_amssoft_fail2ban_rollups')->where('source_log',$path)->first();$r=$row();
    $set=fn($v)=>Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$r['id'])->update($v);
    $future=date('Y-m-d H:i:s',time()+600);
    $set(['processing_state'=>'review','attempts'=>5,'validation_attempts'=>3,'total_attempts'=>5,'total_validation_attempts'=>3,
        'failure_code'=>'filter_positive','failure_detail'=>'Exact proof absent','retry_at'=>$future]);
    file_put_contents($path,$line."\n",FILE_APPEND);BehaviorStore::collect($path);$r=$row();
    check($r['processing_state']==='review'&&(int)$r['validation_attempts']===3,'Collection preserves review');
    check((int)$r['attempts']===5&&$r['retry_at']===$future&&$r['failure_code']==='filter_positive','Collection preserves attempts, feedback and backoff');
    check(BehaviorStore::recoverReviews()===1,'Legacy review receives one corrective round');$r=$row();
    check($r['processing_state']==='retry'&&(int)$r['validation_attempts']===0,'Recovery renews validation epoch only');
    check((int)$r['total_attempts']===5&&(int)$r['total_validation_attempts']===3&&$r['retry_at']===$future,'Recovery preserves totals and backoff');
    check($r['recovery_generation']===AIAnalyzer::RECOVERY_GENERATION&&(int)$r['recovery_rounds']===1,'Generation and round persisted');
    check(!in_array($r['id'],array_column(BehaviorStore::pending(100,true,false,true),'id'),true),'Recovered work cannot bypass backoff');
    for($i=0;$i<3;$i++){BehaviorStore::noteAttempt($row());BehaviorStore::validationFailed($row(),['code'=>'filter_positive','error'=>'Not proven']);}
    $r=$row();check($r['processing_state']==='review'&&(int)$r['total_validation_attempts']===6&&(int)$r['total_attempts']===8,'Failed recovery retains cumulative history');
    check(BehaviorStore::recoverReviews()===0,'Same generation cannot recover forever');
    $set(['recovery_generation'=>null,'recovery_rounds'=>0]);
    check(BehaviorStore::recoverReviews()===0,'Task first failing on current generation cannot self-recover');
    $set(['validation_generation'=>'older-correction']);Database::setConfig('ai_review_auto_recovery_enabled','0');
    check(BehaviorStore::recoverReviews()===0,'UI switch disables recovery');Database::setConfig('ai_review_auto_recovery_enabled','1');
    $set(['bucket'=>date('Y-m-d H:i:s',time()-90000)]);check(BehaviorStore::recoverReviews()===0,'Expired task cannot recover');
    $set(['bucket'=>date('Y-m-d H:i:s'),'failure_code'=>'validation_bridge']);check(BehaviorStore::recoverReviews()===0,'Bridge outage is not regex recovery');
    $set(['failure_code'=>'filter_positive']);check(BehaviorStore::recoverReviews()===1,'Different correction allows another bounded round');
    $set(['processing_state'=>'review','validation_generation'=>AIAnalyzer::RECOVERY_GENERATION]);
    Database::setConfig('ai_review_recovery_limit','2');check(BehaviorStore::recoverReviews()===1,'Configured second round allowed');
    $set(['processing_state'=>'review']);check(BehaviorStore::recoverReviews()===0,'Configured limit remains finite');
    BehaviorStore::requeue($r['id'],1);check((int)$row()['total_validation_attempts']===6,'Manual requeue preserves totals');
    $set(['processing_state'=>'retry','retry_at'=>$future,'attempts'=>2,'validation_attempts'=>1]);
    file_put_contents($path,$line."\n",FILE_APPEND);BehaviorStore::collect($path);
    check($row()['processing_state']==='retry'&&$row()['retry_at']===$future,'Collection also preserves active retry');
    $r=$row();BehaviorStore::acknowledge($r);$total=$r['total_attempts'];
    file_put_contents($path,$line."\n",FILE_APPEND);BehaviorStore::collect($path);
    check($row()['processing_state']==='pending'&&(int)$row()['attempts']===0&&(int)$row()['total_attempts']===$total,'New episode after completion preserves totals');
    $r=$row();$set(['revision'=>$r['revision']+1]);BehaviorStore::acknowledge($r);
    check($row()['analyzed_revision']!==$row()['revision'],'Stale acknowledgement cannot consume new revision');
    Capsule::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>Capsule::raw('revision')]);
    for($i=0;$i<150;$i++)Capsule::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>hash('sha256','repeat'.$path.$i),
        'ip'=>$i<140?'198.51.100.1':'198.51.100.'.($i-138),'source_log'=>$path,'pattern'=>hash('sha256','pattern'.$i),
        'bucket'=>date('Y-m-d H:i:s',time()-2000+$i),'revision'=>1,'events'=>1,'samples'=>'[]']);
    $subjects=BehaviorStore::pending(10,false,false,true);
    check(count($subjects)===10&&count(array_unique(array_column($subjects,'ip')))===10,'Distinct selection sees peers beyond 100 repeats');
    $s=['ip'=>'198.51.100.245','evidence'=>[$line],'failregex'=>'^<HOST> - \S+ \[\s*\] "GET /\.env HTTP/1\.[01]" (?:403|404) \S+'];
    $cache->setValue(null,[]);$d=AutoBanEngine::evidenceFilterDiagnostic($s);check(!empty($d['success']),'Anchored native access regex validated');
    AutoBanEngine::evidenceFilterDiagnostic($s);check(count($cache->getValue())===1,'Identical proof uses cycle cache');
    Database::setConfig('ai_auto_min_confidence','91');AutoBanEngine::evidenceFilterDiagnostic($s);check(count($cache->getValue())===2,'Policy change invalidates cache key');
    $s['failregex']='^<HOST>.*';$d=AutoBanEngine::evidenceFilterDiagnostic($s);check(empty($d['success']),'Unsafe broad regex still refused');
    $cache->setValue(null,null);check($cache->getValue()===null,'Cache disabled outside cycle');
    check(QueueTelemetry::summary()['entries']===null,'Missing metrics are not fabricated as zero');
    $m=['started_at'=>time()-30,'selected'=>10,'completed'=>6,'refused'=>2,'review'=>1,'recovered'=>1,'error'=>'','calls'=>1,'retry_calls'=>1,'duration_seconds'=>30,'reason'=>'queue_not_ready','eligible_ready_start'=>10,'eligible_ready_end'=>4,'eligible_comparable'=>true];
    QueueTelemetry::begin();check(QueueTelemetry::summary()['state']['status']==='running','Cycle start distinct from last API success');
    QueueTelemetry::finish($m);
    Database::incrementConfig('ai_queue_entries_total',3);QueueTelemetry::finish($m);
    Database::incrementConfig('ai_queue_entries_total',3);QueueTelemetry::finish($m);
    $t=QueueTelemetry::summary();check($t['entries']===6&&$t['completed']===12&&$t['capacity']==='draining','Measured entries/completions yield net progress');
    check($t['state']['status']==='completed'&&$t['estimated_cycles']!==null,'Completed cycle and conditional estimate exposed');
    $set(['revision'=>99,'analyzed_revision'=>0,'bucket'=>date('Y-m-d H:i:s',time()-90000)]);
    BehaviorStore::prune();$expired=Database::getConfig('ai_queue_expired_total');BehaviorStore::prune();
    check($expired==='1'&&Database::getConfig('ai_queue_expired_total')==='1','Expired pending task counted once, not completed');
    $m['completed']=0;$m['eligible_comparable']=false;Database::incrementConfig('ai_queue_entries_total',50);QueueTelemetry::finish($m);
    check(QueueTelemetry::summary()['estimated_cycles']===null,'No estimate when entries exceed completions');
    foreach(['ai_review_auto_recovery_enabled','ai_review_recovery_limit'] as $key)check(isset(Policy::fields()[$key]),'Recovery field shared by UI and runtime');
} finally {$cache->setValue(null,null);$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");unlink($path);}
echo "PASS: {$checks} queue recovery/cache/metrics checks; SQL rolled back, fixture removed\n";
