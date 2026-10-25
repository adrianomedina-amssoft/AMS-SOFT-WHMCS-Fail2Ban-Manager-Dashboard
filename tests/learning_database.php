<?php
if(PHP_SAPI!=='cli')exit(1);
$argv[1]='status';ob_start();require dirname(__DIR__).'/scripts/runtime.php';ob_end_clean();
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,BehaviorStore,AttackFamily};
$db=C::connection();if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');
$checks=0;function check($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
$db->beginTransaction();
try{
    if(getenv('AMSFB_TEST_SCHEMA')==='22')Database::setConfig('schema_version','22');
    Database::setConfig('ai_rule_requests','{}');Database::setConfig('ai_behavior_min_events','3');Database::setConfig('ai_behavior_min_ips','2');
    Database::setConfig('ai_behavior_enabled','1');Database::setConfig('ai_behavior_require_repetition','0');
    $source='/var/log/amsfb-learning-'.bin2hex(random_bytes(8)).'.log';$first=null;$firstPattern=null;
    foreach(range(1,100) as $n){
        $ip='198.18.10.'.$n;$path=$n%2?'/wp-admin/':'/blog/wp-includes/wlwmanifest.xml';
        $line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET '.$path.' HTTP/1.1" 403 10 "-" "fixture"';
        $pattern=BehaviorStore::pattern($line);$id=hash('sha256',$source.$n);$event=['id'=>hash('sha256',$id),'ip'=>$ip,'line'=>$line,'time'=>time(),'pattern'=>$pattern];
        C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$id,'ip'=>$ip,'source_log'=>$source,'pattern'=>$pattern,'family_key'=>'wordpress-probe','bucket'=>date('Y-m-d H:i:s'),'revision'=>1,'events'=>1,'samples'=>json_encode([$event])]);
        $s=['ip'=>$ip,'action'=>'ban','confidence'=>99,'source_log'=>$source,'filter_name'=>'provider-name-'.$n,'failregex'=>'^<HOST> attack$','evidence'=>[$line],'_pattern'=>$pattern,'_task_id'=>$id,'_events'=>[$event],'_evidence_validated'=>true];
        $sid=Database::saveSuggestion($s);
        Database::recordDetections($sid,$s);
        check(C::table('mod_amssoft_fail2ban_detections')->where('event_id',$event['id'])->count()===0,'Unvalidated event gained authority');
        $s['_native_validated']=true;Database::recordDetections($sid,$s);Database::recordDetections($sid,$s);
        check(C::table('mod_amssoft_fail2ban_detections')->where('event_id',$event['id'])->count()===1,'Event counted twice');
        if($n===1){$first=$id;$firstPattern=$pattern;BehaviorStore::acknowledge((array)C::table('mod_amssoft_fail2ban_rollups')->where('id',$id)->first());}
        if($n===3){BehaviorStore::revisitCampaigns([$pattern]);check((int)C::table('mod_amssoft_fail2ban_rollups')->where('id',$first)->value('analyzed_revision')===0,'Validated family campaign did not revisit first peer');}
    }
    $stats=Database::familyStats('wordpress-probe',$source,86400,90);
    check($stats['occurrences']===100&&$stats['distinct_ips']===100,'Family fragmented by paths/names');
    check(Database::familyStats('wordpress-probe',$source.'-other',86400,90)['occurrences']===0,'Different origins gained authority');
    check(Database::updateSuggestionStatus($sid,'rejected',1),'Rejection failed');
    check(Database::familyStats('wordpress-probe',$source,86400,90)['occurrences']===99,'Rejected proof remains eligible');
    $replay=$s;$new=Database::saveSuggestion($replay);$replay['_suggestion_id']=$new;
    Database::recordDetections($new,$replay);
    check(C::table('mod_amssoft_fail2ban_detections')->where('event_id',$event['id'])->value('validation_state')==='rejected','Reanalysis resurrected rejected event');
    check(!Database::hasUnrejectedProof($replay),'Rejected own proof authorized automatic ban');
    $replay['_events'][0]['id']=hash('sha256',$event['id'].'new-offset');Database::recordDetections($new,$replay);
    check(Database::hasUnrejectedProof($replay),'New physical event cannot be reconsidered after rejection');
    C::table('mod_amssoft_fail2ban_detections')->where('ip','198.18.10.99')->where('source_log',$source)->update(['validation_state'=>'unknown']);
    check(Database::familyStats('wordpress-probe',$source,86400,90)['occurrences']===99,'Unknown historical state counted');
    C::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$new)->update(['confidence'=>89]);
    check(Database::familyStats('wordpress-probe',$source,86400,90)['occurrences']===98,'Downgraded decision still inflates confidence gate');
    $a=Database::saveSuggestion(['ip'=>'198.18.10.1','source_log'=>$source,'action'=>'monitor','confidence'=>99,'evidence'=>[$line],'_pattern'=>hash('sha256','observation')]);
    check(!in_array($a,Database::getPendingIdsByCountry(''),true),'Observation entered bulk approval');
    $before=Database::getSuggestion($a)['status'];Database::autoDismissDuplicates('198.18.10.1',$sid,1);
    check(Database::getSuggestion($a)['status']===$before,'IP-based duplicate dismissal rewrote observation');
}finally{$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} validated learning database checks; real SQL rolled back, no provider or host mutations\n";
