<?php
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,EvidenceLinks,BehaviorStore,QueueTelemetry,ManagedRules,AIAnalyzer};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();$checks=0;
function check($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');
$db->beginTransaction();
try{
    Database::setConfig('schema_version','22');Database::setConfig('ai_skip_effectively_banned','1');Database::setConfig('ai_auto_min_confidence','90');
    Database::setConfig('ai_rule_requests','{}');Database::setConfig('ai_history_validation_per_cycle','0');
    $source='/var/log/amsfb-links-'.bin2hex(random_bytes(8));$ip='198.18.29.1';
    $line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET /.env HTTP/1.1" 404 10 "-" "fixture"';
    $event=['id'=>hash('sha256',$source),'line'=>$line,'time'=>time(),'pattern'=>hash('sha256','fixture')];
    $s=['ip'=>$ip,'source_log'=>$source,'action'=>'ban','classification'=>'ban','confidence'=>99,'severity'=>'high','threat'=>'fixture',
        'evidence'=>[$line],'failregex'=>'^<HOST> .*env','filter_name'=>'fixture','_evidence_validated'=>true,'_native_validated'=>true,'_events'=>[$event],'_pattern'=>$event['pattern']];
    $first=Database::saveSuggestion($s);$s['_suggestion_id']=$first;Database::recordDetections($first,$s);
    $before=C::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$event['id'])->first();
    // Two independent decisions can cite the same physical attempt.
    $second=C::table('mod_amssoft_fail2ban_ai_suggestions')->insertGetId(['ip'=>$ip,'source_log'=>$source,'classification'=>'ban','confidence'=>99,'severity'=>'high','threat'=>'fixture2','evidence'=>json_encode([$line]),'failregex'=>$s['failregex'],'status'=>'pending','family_key'=>'env-exposure']);
    $s['_suggestion_id']=$second;Database::recordDetections($second,$s);Database::recordDetections($second,$s);
    check(C::table(EvidenceLinks::TABLE)->where('fingerprint',$event['id'])->count()===2,'Associations lost or duplicated');
    $after=C::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$event['id'])->first();
    foreach(['suggestion_id','event_id','detected_at','source_log','evidence'] as $field)check($before->$field===$after->$field,'Physical origin changed: '.$field);
    check(Database::familyStats('env-exposure',$source,86400,90)['occurrences']===1,'Associations multiplied campaign events');
    check(Database::countRecentDetections($ip,60,null,$source,'env-exposure')===1,'Associations multiplied individual events');
    check(Database::hasUnrejectedProof($s),'Second decision lost individual proof');
    $s['_suggestion_id']=$first;check(Database::hasUnrejectedProof($s),'First decision lost individual proof');
    check(Database::updateSuggestionStatus($second,'rejected',1),'Rejection failed');
    check(!Database::hasUnrejectedProof($s),'Physical rejection bypassed via earlier decision');
    Database::recordDetections($first,$s);
    check(C::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$event['id'])->value('validation_state')==='rejected','Rejected physical event resurrected');
    check(C::table(EvidenceLinks::TABLE)->where('fingerprint',$event['id'])->where('validation_state','valid')->count()===2,'Historical validation erased');
    $newId=hash('sha256',$source.'new');EvidenceLinks::link($newId,$first,$s,'unknown','legacy_inferred');
    check(C::table(EvidenceLinks::TABLE)->where('fingerprint',$newId)->value('validation_state')==='unknown','Inferred link became authority');
    EvidenceLinks::migrate();$linksBefore=C::table(EvidenceLinks::TABLE)->count();EvidenceLinks::migrate();
    check(C::table(EvidenceLinks::TABLE)->count()===$linksBefore,'Migration duplicated associations');
    check(C::table(EvidenceLinks::TABLE)->where('fingerprint',$event['id'])->where('origin','native')->count()===2,'Migration replaced original association provenance');
    $jails=[];for($i=0;$i<22;$i++)$jails['amsfb-on-'.$i]=['enabled'=>'true'];for($i=0;$i<44;$i++)$jails['amsfb-off-'.$i]=['enabled'=>'false'];
    check(ManagedRules::inventory($jails)===['enabled'=>22,'disabled'=>44],'Disabled jails occupy active capacity');
    $jails['amsfb-quarantine']=['enabled'=>'yes'];check(ManagedRules::inventory($jails)['enabled']===23,'Enabled quarantine excluded from capacity');
    C::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>C::raw('revision')]);
    C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>hash('sha256',$source.'task'),'ip'=>$ip,'source_log'=>$source,'pattern'=>$event['pattern'],'bucket'=>date('Y-m-d H:i:s'),'events'=>1,'revision'=>1,'samples'=>'[]','blocked_confirmed_at'=>date('Y-m-d H:i:s',time()-600),'blocked_until_check_at'=>date('Y-m-d H:i:s',time()-1)]);
    $health=BehaviorStore::health();check($health['awaiting_recheck']===1&&$health['ready']===0,'Expired confirmation inflated ready queue');
    $cycles=[];for($i=0;$i<3;$i++)$cycles[]=['finished_at'=>time()-60+$i,'error'=>'','reason'=>'queue_not_ready','entries_since_previous'=>1,'expired_since_previous'=>0,'completed'=>2];
    Database::setConfig('ai_cycle_metrics',json_encode($cycles));$t=QueueTelemetry::summary();check($t['capacity']==='awaiting_recheck'&&$t['estimated_cycles']===null,'Stale coverage produced estimate');
    C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$source)->update(['blocked_confirmed_at'=>null,'blocked_until_check_at'=>null]);
    check(BehaviorStore::health()['ready']===1,'Confirmed absence of protection failed to release presentation');
}finally{$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} evidence association/inventory/stale presentation checks; SQL rolled back, no API or native mutation\n";
