<?php
namespace AMS\Fail2Ban {
    class Privileged {public static array $fixture=[];public static array $calls=[];public static function run($args){self::$calls[]=$args[0];if($args[0]!=='protection-snapshot')throw new \RuntimeException('Unexpected native operation '.$args[0]);return self::$fixture;}}
    class Fail2BanClient {public int $bans=0;public function banIP(...$a){$this->bans++;throw new \RuntimeException('No native ban permitted');}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{Database,DecisionProtection,Privileged,Fail2BanClient,AutoBanEngine,BehaviorStore};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
class ProtectedWorkerAI extends \AMS\Fail2Ban\AIAnalyzer {
    public int $calls=0;
    public function analyzeSubjects(array $lines,array $context): array {
        $this->requestStarting();$this->calls++;$out=[];
        foreach($context as $ip=>$ctx)$out[]=['ip'=>$ip,'action'=>'monitor','severity'=>'low','confidence'=>99,'threat'=>'fixture',
            'evidence'=>array_values(array_filter($lines,fn($l)=>\AMS\Fail2Ban\Safety::sourceIp($l)===$ip)),'filter_name'=>'','failregex'=>''];
        return $out;
    }
}
if(!C::schema()->hasTable(DecisionProtection::TABLE))throw new RuntimeException('Projection table must be provisioned explicitly; test never migrates.');
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy; retry without changes.');
$db->beginTransaction();$checks=0;function projectionCheck($ok,$message){global $checks;if(!$ok)throw new RuntimeException($message);$checks++;}
try{
    Database::setConfig('schema_version','24');Database::setConfig('ai_skip_effectively_banned','0');
    projectionCheck(\AMS\Fail2Ban\BlockedTasks::enabled()&&\AMS\Fail2Ban\Policy::number('ai_skip_effectively_banned')===1,'Mandatory exclusion disabled by stored flag');
    try{\AMS\Fail2Ban\Policy::validate(['ai_skip_effectively_banned'=>'0'],\AMS\Fail2Ban\Policy::values());projectionCheck(false,'Policy allowed bypass');}catch(InvalidArgumentException $e){projectionCheck(true,'Policy rejects bypass');}
    Database::setConfig('ai_skip_effectively_banned','1');
    C::table('mod_amssoft_fail2ban_ai_suggestions')->where('status','pending')->update(['status'=>'rejected']);
    $ids=[];$nonce=bin2hex(random_bytes(8));
    foreach(['actionable','protected','checking','review','history'] as $i=>$view){
        $ip='198.18.51.'.($i+1);$time=$view==='history'?time()-90000:time();
        $line=$ip.' - - ['.date('d/M/Y:H:i:s O',$time).'] "GET /projection-'.$nonce.' HTTP/1.1" 404 10 "-" "fixture"';
        $data=['ip'=>$ip,'source_log'=>$view==='checking'?'/var/log/unknown.log':'/var/log/apache2/access_whmcs.log','action'=>'ban','confidence'=>99,'severity'=>'high','evidence'=>[$line],
            '_pattern'=>BehaviorStore::pattern($line),'_analysis_key'=>hash('sha256',$nonce.$view),'_task_id'=>hash('sha256',$nonce.'task'.$view),
            'decision_code'=>$view==='review'?'filter_positive':'waiting_threshold'];
        $ids[$view]=Database::saveSuggestion($data);
    }
    $snapshot=['success'=>true,'stable'=>true,'observed_at'=>time(),'ttl'=>300,'errors'=>[],'requirements'=>['http'=>[80,443],'ssh'=>[2222]],
        'entries'=>[['ip'=>'198.18.51.2','jail'=>'fixture-other','ticket'=>'fixture','effective'=>true,'protocol'=>'tcp','ports'=>[80,443],'expires_at'=>time()+3600]]];
    Privileged::$fixture=$snapshot;$projection=DecisionProtection::refresh($snapshot);
    foreach($ids as $view=>$id)projectionCheck($projection['groups'][$view]===[$id],'Wrong decision view '.$view);
    $page=Database::getPendingSuggestionsPaged(99,10);projectionCheck($page['total']===1&&$page['page']===1&&$page['data'][0]['id']===$ids['actionable'],'Pagination counts before exclusion');
    projectionCheck(Database::countPendingSuggestions()===1,'Dashboard counter includes nonactionable decisions');
    $protected=Database::getPendingSuggestionsPaged(1,10,'protected');projectionCheck($protected['total']===1&&$protected['data'][0]['id']===$ids['protected'],'Protected tab');
    projectionCheck(Database::getPendingIdsByCountry('')===[$ids['actionable']],'Country bulk IDs include nonactionable decision');
    $groups=Database::getPendingGroupedByCountry();projectionCheck(array_sum(array_column($groups,'ip_count'))===1,'Country count includes protected');
    $client=new Fail2BanClient;$engine=new AutoBanEngine(null,$client);
    foreach(['review','history'] as $view)projectionCheck(!$engine->approveSuggestion($ids[$view],0),'Direct-ID bypassed '.$view.' admission');
    projectionCheck($engine->approveSuggestion($ids['protected'],0),'Already protected direct-ID action should be idempotent');
    projectionCheck($client->bans===0&&Database::getSuggestion($ids['protected'])['decision_code']==='protected_existing','Protected action renewed ban');
    Privileged::$fixture=['success'=>false];
    $before=Database::getSuggestion($ids['actionable'])['status'];
    projectionCheck(!$engine->approveSuggestion($ids['actionable'],0),'Unavailable query authorized ban');
    projectionCheck(Database::getSuggestion($ids['actionable'])['status']===$before&&$client->bans===0,'Unavailable query changed decision');
    $failed=DecisionProtection::refresh(Privileged::$fixture);
    projectionCheck(count($failed['groups']['actionable'])===0&&count($failed['groups']['protected'])===0&&count($failed['groups']['checking'])===5,'Failed query not segregated');
    projectionCheck(C::table(DecisionProtection::TABLE)->whereIn('suggestion_id',array_values($ids))->count()===5,'Projection not persisted');
    // A new pattern for the same individually validated suspect gets priority;
    // other IPs/origins, low confidence and rejected physical proof do not.
    $suspect=Database::getSuggestion($ids['actionable']);$suspect['evidence']=json_decode($suspect['evidence'],true);$line=$suspect['evidence'][0];$fingerprint=hash('sha256',$nonce.'priority');
    $suspect['_evidence_validated']=true;$suspect['_native_validated']=true;
    $suspect['_events']=[['id'=>$fingerprint,'ip'=>$suspect['ip'],'line'=>$line,'time'=>time(),'pattern'=>$suspect['pattern']]];
    Database::recordDetections($ids['actionable'],$suspect);
    $priorityTask=hash('sha256',$nonce.'priority-task');
    C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$priorityTask,'ip'=>$suspect['ip'],'source_log'=>$suspect['source_log'],
        'pattern'=>hash('sha256','new-pattern'),'bucket'=>date('Y-m-d H:i:s'),'events'=>1,'revision'=>1,'samples'=>'[]']);
    projectionCheck(in_array($priorityTask,array_column(BehaviorStore::pending(100,null,true),'id'),true),'New pattern for validated suspect lost priority');
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$priorityTask)->update(['ip'=>'198.18.51.200']);
    projectionCheck(!in_array($priorityTask,array_column(BehaviorStore::pending(100,null,true),'id'),true),'Another IP inherited priority');
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$priorityTask)->update(['ip'=>$suspect['ip'],'source_log'=>'/var/log/apache2/error_whmcs.log']);
    projectionCheck(!in_array($priorityTask,array_column(BehaviorStore::pending(100,null,true),'id'),true),'Another origin inherited priority');
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$priorityTask)->update(['source_log'=>$suspect['source_log']]);
    C::table(\AMS\Fail2Ban\EvidenceLinks::TABLE)->where('fingerprint',$fingerprint)->update(['confidence'=>89]);
    projectionCheck(!in_array($priorityTask,array_column(BehaviorStore::pending(100,null,true),'id'),true),'Low-confidence association granted priority');
    C::table(\AMS\Fail2Ban\EvidenceLinks::TABLE)->where('fingerprint',$fingerprint)->update(['confidence'=>99]);
    C::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$fingerprint)->update(['validation_state'=>'rejected']);
    projectionCheck(!in_array($priorityTask,array_column(BehaviorStore::pending(100,null,true),'id'),true),'Rejected proof granted priority');
    C::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$fingerprint)->update(['validation_state'=>'valid']);
    C::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$ids['actionable'])->update(['confidence'=>89]);
    projectionCheck(!in_array($priorityTask,array_column(BehaviorStore::pending(100,null,true),'id'),true),'Low-confidence proof granted priority');
    C::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$ids['actionable'])->update(['confidence'=>99]);
    // Real worker/admission, fake provider/native, rollback-only fixture.
    C::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>C::raw('revision')]);
    C::table(\AMS\Fail2Ban\AnalysisWork::BATCH_TABLE)->update(['status'=>'complete']);
    foreach(['ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold','ai_cycle_max_calls'=>'1','ai_cycle_seconds'=>'180','ai_history_validation_per_cycle'=>'0',
        'ai_review_auto_recovery_enabled'=>'0','ai_rule_requests'=>'{}','ai_auto_create_filter'=>'0','ai_whitelist_ips'=>''] as $k=>$v)Database::setConfig($k,$v);
    $ip='198.18.51.2';$task=hash('sha256',$nonce.'worker');$line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET /worker-'.$nonce.' HTTP/1.1" 200 10 "-" "fixture"';
    $pattern=BehaviorStore::pattern($line);$event=['id'=>hash('sha256',$task.'event'),'ip'=>$ip,'pattern'=>$pattern,'line'=>$line,'time'=>time()];
    C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$task,'ip'=>$ip,'source_log'=>'/var/log/apache2/access_whmcs.log','pattern'=>$pattern,
        'bucket'=>date('Y-m-d H:i:s',(int)(floor(time()/600)*600)),'events'=>1,'revision'=>1,'samples'=>json_encode([$event])]);
    $ai=new ProtectedWorkerAI('openai','fixture');$worker=new AutoBanEngine($ai,$client);Privileged::$fixture=$snapshot;$worker->runAnalysis();
    $r=C::table('mod_amssoft_fail2ban_rollups')->where('id',$task)->first();
    projectionCheck($ai->calls===0&&$r->blocked_confirmed_at!==null&&(int)$r->analyzed_revision===0,'Protected subject sent to provider or acknowledged');
    Privileged::$fixture=['success'=>false];$worker->runAnalysis();$r=C::table('mod_amssoft_fail2ban_rollups')->where('id',$task)->first();
    projectionCheck($ai->calls===0&&$r->retry_at!==null&&(int)$r->attempts===0&&(int)$r->total_attempts===0&&$r->failure_code==='coverage_unavailable','Unavailable query spent API attempt or lost task');
    Privileged::$fixture=$snapshot;Privileged::$fixture['entries']=[];
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$task)->update(['retry_at'=>null]);
    $worker->runAnalysis();$r=C::table('mod_amssoft_fail2ban_rollups')->where('id',$task)->first();
    projectionCheck($ai->calls===1&&(int)$r->analyzed_revision===1&&(int)$r->total_attempts===1,'Unprotected subject not processed after local recovery');
    projectionCheck($client->bans===0,'Worker fixture executed native ban');
    // Saved provider responses must survive local coverage outages without
    // an acknowledgement or another paid request after recovery.
    $savedTask=hash('sha256',$nonce.'saved-worker');$savedRow=(array)$r;
    $savedRow['id']=$savedTask;$savedRow['analyzed_revision']=0;$savedRow['attempts']=0;$savedRow['total_attempts']=0;
    $savedRow['processing_state']='pending';$savedRow['retry_at']=null;
    C::table('mod_amssoft_fail2ban_rollups')->insert($savedRow);
    $context=[$ip=>['task_id'=>$savedTask,'source_log'=>$savedRow['source_log'],'pattern'=>$pattern]];
    $raw=[['ip'=>$ip,'action'=>'monitor','severity'=>'low','confidence'=>99,'threat'=>'saved fixture','evidence'=>[$line],'filter_name'=>'','failregex'=>'']];
    $checkpoint=\AMS\Fail2Ban\AnalysisWork::saveBatch([$savedRow],[$ip=>[$event]],$context,$raw);
    Privileged::$fixture=['success'=>false];$worker->runAnalysis();
    projectionCheck(C::table(\AMS\Fail2Ban\AnalysisWork::BATCH_TABLE)->where('id',$checkpoint)->value('status')==='pending','Coverage outage discarded saved response');
    projectionCheck((int)C::table('mod_amssoft_fail2ban_rollups')->where('id',$savedTask)->value('analyzed_revision')===0&&$ai->calls===1,'Coverage outage acknowledged replay or called provider');
    Privileged::$fixture=$snapshot;Privileged::$fixture['entries']=[];$worker->runAnalysis();
    projectionCheck((int)C::table('mod_amssoft_fail2ban_rollups')->where('id',$savedTask)->value('analyzed_revision')===1&&$ai->calls===1,'Saved response not resumed locally after recovery: '.json_encode([
        'calls'=>$ai->calls,'revision'=>C::table('mod_amssoft_fail2ban_rollups')->where('id',$savedTask)->value('analyzed_revision'),
        'status'=>C::table(\AMS\Fail2Ban\AnalysisWork::BATCH_TABLE)->where('id',$checkpoint)->value('status'),'error'=>Database::getConfig('ai_last_error')]));
}finally{DecisionProtection::reset();$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} decision projection/action checks; SQL rolled back, fake coverage, no API/native mutations\n";
}
