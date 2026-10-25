<?php
// Real schema-23 repositories; all fixtures rolled back, no API/native calls.
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,Policy,BehaviorStore,DecisionMemory,AnalysisWork};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
if((int)Database::getConfig('schema_version','0')<23)throw new RuntimeException('Schema 23 required; test never migrates.');
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy; no writes made.');
$db->beginTransaction();$checks=0;
function checkRepo($value,$message){global $checks;if(!$value)throw new RuntimeException($message);$checks++;}
try {
    Database::setConfig('schema_version','23'); // Legacy structural contract; schema25 has separate admission coverage.
    foreach(['ai_queue_consolidation'=>'1','ai_reuse_enabled'=>'1','ai_reuse_min_confidence'=>'95','ai_reuse_minutes'=>'30','ai_reuse_sample_percent'=>'1','ai_reuse_activity_multiplier'=>'2'] as $key=>$value)Database::setConfig($key,$value);
    $source='/var/log/apache2/access_whmcs.log';$nonce=bin2hex(random_bytes(8));$now=time();$bucket=(int)(floor($now/600)*600);
    $rows=[];
    for($i=0;$i<2;$i++){
        $stamp=$bucket-600+$i*600;
        $line='198.18.229.17 - - ['.date('d/M/Y:H:i:s O',$stamp).'] "GET /repository-'.$nonce.' HTTP/1.1" 200 10 "-" "fixture"';
        $pattern=BehaviorStore::pattern($line);$id=hash('sha256',$nonce.$i);
        $event=['id'=>hash('sha256',$id.'event'),'ip'=>'198.18.229.17','line'=>$line,'time'=>$stamp,'pattern'=>$pattern];
        $row=['id'=>$id,'ip'=>$event['ip'],'source_log'=>$source,'pattern'=>$pattern,'bucket'=>date('Y-m-d H:i:s',$stamp),'events'=>1,'revision'=>1,'analyzed_revision'=>0,'samples'=>json_encode([$event]),'processing_state'=>'pending','attempts'=>0,'validation_attempts'=>0,'behavior_complete'=>1,'behavior_variants'=>json_encode([DecisionMemory::lineSignature($line,$event['ip'])])];
        C::table('mod_amssoft_fail2ban_rollups')->insert($row);$rows[]=(array)C::table('mod_amssoft_fail2ban_rollups')->where('id',$id)->first();
    }
    checkRepo(DecisionMemory::signature($rows[0])===DecisionMemory::signature($rows[1]),'Timestamp-only change altered signature');
    $group=AnalysisWork::consolidate([$rows[0]])[0];
    checkRepo(count($group['_work_refs'])===2&&count($group['_work_events'])===2,'Real consolidation lost references/proof');
    $proofs=[$group['ip']=>$group['_work_events']];$contexts=[$group['ip']=>['task_id'=>$group['id']]];
    $raw=[['ip'=>$group['ip'],'action'=>'monitor','confidence'=>99,'evidence'=>array_column($group['_work_events'],'line')]];
    $checkpoint=AnalysisWork::saveBatch([$group],$proofs,$contexts,$raw);
    $restored=AnalysisWork::nextBatch();
    checkRepo($restored&&$restored['id']===$checkpoint&&$restored['raw']===$raw,'Real checkpoint did not restore frozen response');
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$rows[1]['id'])->update(['revision'=>2,'events'=>2,'processing_state'=>'review','failure_code'=>'fixture_concurrent']);
    AnalysisWork::finalize($group);
    checkRepo((int)C::table('mod_amssoft_fail2ban_rollups')->where('id',$rows[0]['id'])->value('analyzed_revision')===1,'Representative CAS did not complete');
    $raced=C::table('mod_amssoft_fail2ban_rollups')->where('id',$rows[1]['id'])->first();
    checkRepo((int)$raced->revision===2&&(int)$raced->analyzed_revision===0&&$raced->processing_state==='review','CAS overwrote later revision/review');
    AnalysisWork::markItem($checkpoint,$group['id']);
    checkRepo(C::table(AnalysisWork::BATCH_TABLE)->where('id',$checkpoint)->value('status')==='complete','Checkpoint not completed');
    checkRepo(C::table(AnalysisWork::TABLE)->where('rollup_id',$rows[1]['id'])->value('result_state')==='pending','Unconfirmed reference recorded as completed');
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$rows[0]['id'])->update(['analyzed_revision'=>0,'campaign_signature'=>hash('sha256',$nonce.'new-campaign')]);
    $reopened=(array)C::table('mod_amssoft_fail2ban_rollups')->where('id',$rows[0]['id'])->first();
    $again=AnalysisWork::consolidate([$reopened]);
    checkRepo(count($again)===1,'Terminal metadata blocked legitimate campaign recheck');
    AnalysisWork::finalize($again[0]);
    checkRepo((int)C::table('mod_amssoft_fail2ban_rollups')->where('id',$rows[0]['id'])->value('analyzed_revision')===1,'Reopened campaign not acknowledged');
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$rows[1]['id'])->update(['revision'=>1,'events'=>1,'processing_state'=>'pending','failure_code'=>null]);
    $row=$rows[0];$item=['ip'=>$row['ip'],'source_log'=>$source,'_pattern'=>$row['pattern'],'_task_id'=>$row['id'],'_analysis_key'=>hash('sha256',$nonce.'decision'),'action'=>'monitor','confidence'=>99,'evidence'=>array_column($proofs[$row['ip']],'line'),'_events'=>$proofs[$row['ip']],'threat'=>'Fixture'];
    $id=Database::saveSuggestion($item);DecisionMemory::remember($row,$item,$id);
    $memory=C::table(DecisionMemory::TABLE)->where('suggestion_id',$id)->first();
    checkRepo($memory&&(int)$memory->baseline_events===2,'Real memory did not store aggregate baseline');
    checkRepo(strtotime($memory->valid_until)-strtotime($memory->created_at)===1800,'UI TTL not applied');
    $until=$memory->valid_until;
    $window=intdiv(time(),1800);
    $sample=hexdec(substr(hash('sha256',$memory->key."\0".$row['bucket']."\0".$window),0,8))%100;
    checkRepo(DecisionMemory::reusable($row)===($sample>=1),'Real memory hit differs from deterministic sample');
    checkRepo(C::table(DecisionMemory::TABLE)->where('key',$memory->key)->value('valid_until')===$until,'Lookup renewed TTL');
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$rows[1]['id'])->update(['events'=>3]);
    checkRepo(!DecisionMemory::reusable($row),'Activity doubling failed to invalidate memory');
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$rows[1]['id'])->update(['events'=>1]);
    Database::updateSuggestionStatus($id,'rejected',0);
    checkRepo(!DecisionMemory::reusable($row),'Rejected decision was reused');
    checkRepo(!Database::updateSuggestionStatus($id,'auto_executed'),'Revoked decision overwritten');
    $health=AnalysisWork::health();checkRepo(isset($health['unique_subjects_ready'],$health['pending_batches']),'Real repository health unavailable');
} finally {$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} structural repository checks; real SQL rolled back, no DDL/API/native\n";
