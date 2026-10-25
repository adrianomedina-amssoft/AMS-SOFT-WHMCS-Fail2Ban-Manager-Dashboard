<?php
if(PHP_SAPI!=='cli')exit(1);
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__,4).'/configuration.php';
require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{Database,BehaviorStore,Policy,AIAnalyzer,AutoBanEngine,Fail2BanClient,Safety};
use WHMCS\Database\Capsule;
$c=new Capsule();$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
$checks=0;function check($v,$message){global $checks;if(!$v)throw new RuntimeException($message);$checks++;}
class ObserveOnlyAI extends AIAnalyzer {
    public int $fresh=0,$retry=0;
    public array $batches=[];
    public function analyzeSubjects(array $lines,array $context): array {
        $this->requestStarting();
        if(str_starts_with(reset($context)['source_log'],'/var/log/retry'))$this->retry++;else $this->fresh++;
        $this->batches[]=array_column($context,'task_id');
        $result=[];
        foreach($context as $ip=>$data)$result[]=['ip'=>$ip,'action'=>'monitor','severity'=>'low','confidence'=>99,
            'threat'=>'Fixture observation','evidence'=>Safety::evidence($lines,$ip),'filter_name'=>'','failregex'=>''];
        return $result;
    }
}
$db=Capsule::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)
    throw new RuntimeException('Production cycle still active; rerun after it completes');
$db->beginTransaction();
Database::setConfig('schema_version','23'); // Legacy worker regression; mandatory admission has schema24 tests.
Database::setConfig('ai_rule_requests','{}');Database::setConfig('ai_history_validation_per_cycle','0');
try {
    Capsule::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>Capsule::raw('revision')]);
    foreach(['ai_auto_enabled'=>'1','ai_mode'=>'suggestion','ai_auto_create_filter'=>'0','ai_cycle_max_calls'=>'10',
        'ai_retry_call_percent'=>'30','ai_validation_max_attempts'=>'3','ai_queue_urgent_enabled'=>'1',
        'ai_queue_turn_fresh'=>'0','ai_queue_turn_retry'=>'0'] as $k=>$v)Database::setConfig($k,$v);
    $ids=[];
    for($i=1;$i<=160;$i++) {
        $ip='198.51.100.'.$i;$line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET /clientarea.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"';
        $id=hash('sha256','operation-fixture'.bin2hex(random_bytes(8)));$ids[]=$id;$pattern=BehaviorStore::pattern($line);
        $event=['id'=>hash('sha256',$id),'ip'=>$ip,'pattern'=>$pattern,'time'=>time(),'line'=>$line];
        Capsule::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$id,'ip'=>$ip,'source_log'=>$i>120?'/var/log/retry-fixture':'/var/log/fresh-fixture',
            'pattern'=>$pattern,'bucket'=>date('Y-m-d H:i:s',time()-600),'revision'=>1,'events'=>1,'samples'=>json_encode([$event]),
            'attempts'=>$i>120?1:0,'processing_state'=>$i>120?'retry':'pending']);
        if(($i>=111&&$i<=120)||$i>=151)Database::saveSuggestion(['ip'=>$ip,'source_log'=>$i>120?'/var/log/retry-fixture':'/var/log/fresh-fixture',
            '_pattern'=>$pattern,'_task_id'=>$id,'_analysis_key'=>hash('sha256',$id.'urgent'),'action'=>'ban','confidence'=>99,'filter_name'=>'fixture-urgent']);
    }
    $ai=new ObserveOnlyAI('openai','fixture');$engine=new AutoBanEngine($ai,new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client'));
    $engine->runAnalysis();
    check($ai->fresh===7&&$ai->retry===3,'Fresh backlog receives 70% and retry receives 30% of ten calls');
    check(Database::getConfig('ai_last_cycle_calls')==='10'&&Database::getConfig('ai_last_cycle_retry_calls')==='3','Cycle counters persisted');
    check(count(array_intersect($ai->batches[0],array_slice($ids,110,10)))===10,'First fresh call selects urgent tasks');
    check(count(array_intersect($ai->batches[1],array_slice($ids,150,10)))===10,'First retry call selects urgent tasks');
    check(!array_intersect($ai->batches[2],array_slice($ids,150,10)),'Second retry call serves old tasks');
    check(!array_intersect($ai->batches[4],array_slice($ids,110,10)),'Second fresh call serves old tasks');
    check(Database::getConfig('ai_queue_turn_fresh')==='1'&&Database::getConfig('ai_queue_turn_retry')==='1','Urgent/old turns persist across cycles, including small budgets');
    $row=(array)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$ids[110])->first();
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->update(['analyzed_revision'=>0,'processing_state'=>'pending','attempts'=>0]);
    $row=(array)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->first();
    $bad=['code'=>'filter_host','error'=>'Each expression needs exactly one HOST'];
    for($i=0;$i<3;$i++) {BehaviorStore::validationFailed($row,$bad);$row=(array)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->first();}
    check($row['processing_state']==='review'&&(int)$row['validation_attempts']===3,'Three validation failures move only this revision to technical review');
    check(!in_array($row['id'],array_column(BehaviorStore::pending(1000),'id'),true),'Technical review does not consume automatic retry queue');
    try{BehaviorStore::requeue($row['id'],0);check(false,'Anonymous requeue accepted');}catch(InvalidArgumentException $e){check(true,'Admin required');}
    BehaviorStore::requeue($row['id'],1);
    $row=(array)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->first();
    check($row['processing_state']==='pending'&&(int)$row['validation_attempts']===0,'Manual requeue resets validation budget without ban');
    BehaviorStore::validationFailed($row,['code'=>'bridge_error','error'=>'Unavailable']);
    check((int)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->value('validation_attempts')===0,'Bridge failures never count as unsafe regex');
    $proof=BehaviorStore::proofEvents($row);
    check(count($proof)===1&&$proof[0]['ip']===$row['ip'],'Proof confined to complete same-IP/source/pattern events');
    foreach(['origin','pattern'] as $different) {
        $copy=$row;$copy['id']=hash('sha256','different-'.$different.bin2hex(random_bytes(8)));
        if($different==='origin')$copy['source_log']='/var/log/unrelated-fixture';else $copy['pattern']=hash('sha256','unrelated-pattern');
        Capsule::table('mod_amssoft_fail2ban_rollups')->insert($copy);
        check(count(BehaviorStore::proofEvents($row))===1,'Same peer cannot borrow proof from another '.$different);
    }
    $bound=Safety::bindSuggestions([['ip'=>$row['ip'],'action'=>'ban','evidence'=>['invented historical attack']]],array_column($proof,'line'));
    check(!$bound[0]['_evidence_validated'],'Invented/history-only citation cannot authorize ban');
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->update(['revision'=>2]);
    BehaviorStore::acknowledge($row);
    check((int)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->value('analyzed_revision')===0,'Acknowledgement cannot consume a concurrent newer revision');
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->update(['processing_state'=>'review','bucket'=>date('Y-m-d H:i:s',time()-90000)]);
    try{BehaviorStore::requeue($row['id'],1);check(false,'Old proof allowed');}catch(InvalidArgumentException $e){check(true,'Outside-window review cannot authorize recent ban');}
    check(BehaviorStore::health()['outside_window']>=1,'Outside-window backlog remains visible');
    // With one call per cycle, urgency must not starve old work forever.
    Capsule::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>Capsule::raw('revision')]);
    $smallUrgent=[];$smallOld=[];
    for($i=161;$i<=200;$i++) {
        $id=hash('sha256','small-budget'.random_bytes(8));$ip='198.51.100.'.$i;
        $line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET /clientarea.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"';
        $pattern=BehaviorStore::pattern($line);$urgent=$i<=180;
        Capsule::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$id,'ip'=>$ip,'source_log'=>'/var/log/fresh-small',
            'pattern'=>$pattern,'bucket'=>date('Y-m-d H:i:s',time()-($urgent?300:3600)),'revision'=>1,'events'=>1,
            'samples'=>json_encode([['id'=>hash('sha256',$id),'ip'=>$ip,'pattern'=>$pattern,'time'=>time(),'line'=>$line]])]);
        if($urgent) {
            $smallUrgent[]=$id;Database::saveSuggestion(['ip'=>$ip,'source_log'=>'/var/log/fresh-small','_pattern'=>$pattern,
                '_task_id'=>$id,'_analysis_key'=>hash('sha256',$id.'urgent'),'action'=>'ban','confidence'=>99]);
        } else $smallOld[]=$id;
    }
    Database::setConfig('ai_cycle_max_calls','1');Database::setConfig('ai_queue_turn_fresh','0');
    $small=new ObserveOnlyAI('openai','fixture');$smallEngine=new AutoBanEngine($small,new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client'));
    $smallEngine->runAnalysis();$smallEngine->runAnalysis();
    check(count(array_intersect($small->batches[0],$smallUrgent))===10,'Small budget first cycle serves urgent work');
    check(count(array_intersect($small->batches[1],$smallOld))===10,'Small budget second cycle serves old work despite remaining urgency');
} finally {$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} operational database checks; fake API, observation-only engine, SQL rolled back\n";
