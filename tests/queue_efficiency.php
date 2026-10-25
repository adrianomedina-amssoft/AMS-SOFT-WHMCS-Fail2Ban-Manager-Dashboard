<?php
if(PHP_SAPI!=='cli')exit(1);
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__,4).'/configuration.php';
require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule;
use AMS\Fail2Ban\{Database,BehaviorStore,Policy,Migrations};
$c=new Capsule();$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
$db=Capsule::connection();$checks=0;
function verify($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy; rerun');
$db->beginTransaction();
try {
    Migrations::run();Migrations::run(); // Settings migration must also roll back.
    Database::setConfig('schema_version','23'); // Legacy exact-task priority; schema24 suspect priority has dedicated coverage.
    $pattern=hash('sha256',random_bytes(16));$source='/var/log/queue-efficiency-fixture';
    Database::setConfig('ai_behavior_enabled','1');Database::setConfig('ai_behavior_require_repetition','0');
    Database::setConfig('ai_behavior_min_events','3');Database::setConfig('ai_behavior_min_ips','2');
    $insert=function($n,$age=0)use($source,$pattern){
        $line='198.51.100.'.$n.' - - ['.date('d/M/Y:H:i:s O',time()-$age).'] "GET /.env HTTP/1.1" 404 10 "-" "fixture"';
        $events=[];foreach([0,1] as $index)$events[]=['id'=>hash('sha256',$source.$n.$index),'ip'=>'198.51.100.'.$n,'line'=>$line,'time'=>time()-$age,'pattern'=>$pattern];
        $id=hash('sha256',$pattern.$n);Capsule::table('mod_amssoft_fail2ban_rollups')->insert([
            'id'=>$id,'ip'=>'198.51.100.'.$n,'source_log'=>$source,'pattern'=>$pattern,'bucket'=>date('Y-m-d H:i:s',time()-$age),
            'events'=>2,'revision'=>1,'analyzed_revision'=>1,'samples'=>json_encode($events),'family_key'=>'env-exposure','processing_state'=>'processed']);
        if($n!==201){$s=['ip'=>'198.51.100.'.$n,'source_log'=>$source,'_pattern'=>$pattern,'action'=>'ban','confidence'=>99,'status'=>'approved','evidence'=>[$line],
            '_events'=>$events,'_evidence_validated'=>true,'_native_validated'=>true];Database::recordDetections(Database::saveSuggestion($s),$s);}
        return $id;
    };
    $one=$insert(201,3600);$two=$insert(202,1800);
    $row=fn($id)=>(array)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$id)->first();
    $data=['ip'=>'198.51.100.201','source_log'=>$source,'_pattern'=>$pattern,'action'=>'ban','confidence'=>99,
        'filter_name'=>'fixture-env','failregex'=>'^<HOST> attack$','_task_id'=>$one,'_analysis_key'=>hash('sha256',$one.'attempt')];
    $suggestion=Database::saveSuggestion($data);
    $proof=$row($one);$data['evidence']=array_column(json_decode($proof['samples'],true),'line');$data['_events']=json_decode($proof['samples'],true);
    $data['_evidence_validated']=$data['_native_validated']=true;
    Database::saveSuggestion($data);Database::recordDetections($suggestion,$data);
    $same=Database::saveSuggestion(array_replace($data,['filter_name'=>'fixture-corrected','reason'=>'Corrected feedback']));
    verify($same===$suggestion,'Same task/revision/campaign reuses pending row even if regex name changes');
    verify(Database::getSuggestion($same)['filter_name']==='fixture-corrected','Pending suggestion receives corrected filter name');
    BehaviorStore::acknowledge($row($one));
    verify(!empty($row($one)['campaign_signature']),'Acknowledgement baselines campaign');
    BehaviorStore::revisitCampaigns([$pattern]);
    verify((int)$row($one)['analyzed_revision']===1,'Unchanged campaign never reopens processed task');
    $three=$insert(203);
    BehaviorStore::revisitCampaigns([$pattern]);
    verify((int)$row($one)['analyzed_revision']===0,'New participant reopens individually suspicious task');
    verify((int)$row($two)['analyzed_revision']===1,'No collective requeue of innocent peers');
    $stamp=$row($one)['last_revisit_at'];BehaviorStore::revisitCampaigns([$pattern]);
    verify($row($one)['last_revisit_at']===$stamp,'Already queued task is not scheduled again');
    BehaviorStore::acknowledge($row($one));$four=$insert(204);
    BehaviorStore::revisitCampaigns([$pattern]);
    verify((int)$row($one)['analyzed_revision']===1,'New member cannot bypass cooldown');
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$one)->update(['last_revisit_at'=>date('Y-m-d H:i:s',time()-14401),'retry_at'=>date('Y-m-d H:i:s',time()+600)]);
    BehaviorStore::revisitCampaigns([$pattern]);
    verify((int)$row($one)['analyzed_revision']===1,'Campaign cannot bypass backoff');
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$one)->update(['retry_at'=>null,'processing_state'=>'review','validation_attempts'=>3]);
    BehaviorStore::revisitCampaigns([$pattern]);
    verify($row($one)['processing_state']==='review','Campaign cannot bypass technical review');
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$one)->update(['processing_state'=>'processed','validation_attempts'=>2,'attempts'=>2]);
    BehaviorStore::revisitCampaigns([$pattern]);
    verify((int)$row($one)['analyzed_revision']===0&&(int)$row($one)['validation_attempts']===2&&(int)$row($one)['attempts']===2,'Campaign preserves retry and validation budgets');
    $urgent=BehaviorStore::pending(5000,true,true);
    verify(in_array($one,array_column($urgent,'id'),true),'Urgency binds exact task, source and pattern');
    Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$suggestion)->update(['task_id'=>$two]);
    verify(!in_array($one,array_column(BehaviorStore::pending(5000,true,true),'id'),true),'Different task cannot grant urgency');
    Database::updateSuggestionStatus($suggestion,'rejected',1);
    $new=Database::saveSuggestion($data);
    verify($new!==$suggestion&&Database::getSuggestion($suggestion)['status']==='rejected','Resolved suggestion remains immutable');
    $health=BehaviorStore::health();
    verify(isset($health['ready'],$health['backoff'],$health['revisits_avoided']),'Queue exposes ready/backoff/revisit metrics');
    Database::setConfig('ai_behavior_min_events','100');
    $proof=$row($one);$event=json_decode($proof['samples'],true)[0];$event['id']=hash('sha256',$one.'new-after-rejection');
    $event['time']=time();$event['line']=str_replace('['.date('d/M/Y:H:i:s O',time()-3600).']','['.date('d/M/Y:H:i:s O').']',$event['line']);
    $data['evidence']=[$event['line']];$data['_events']=[$event];
    Database::saveSuggestion($data);Database::recordDetections($new,$data);
    BehaviorStore::acknowledge($row($one));
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$one)->update(['last_revisit_at'=>null]);
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$two)->update(['events'=>100]);
    $proof=$row($two);$events=json_decode($proof['samples'],true);$many=[];
    foreach(range(1,100) as $n){$event=$events[0];$event['id']=hash('sha256',$two.'crossing'.$n);$many[]=$event;}
    $s=['ip'=>$proof['ip'],'source_log'=>$source,'_pattern'=>$pattern,'action'=>'ban','confidence'=>99,'status'=>'approved','evidence'=>array_column($events,'line'),
        '_events'=>$many,'_evidence_validated'=>true,'_native_validated'=>true];
    Database::recordDetections(Database::saveSuggestion($s),$s);
    Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$new)->update(['task_id'=>$one]);
    BehaviorStore::revisitCampaigns([$pattern]);
    verify((int)$row($one)['analyzed_revision']===0,'First threshold crossing reopens task without requiring another peer');
    foreach(['ai_campaign_revisit_minutes','ai_queue_urgent_enabled','ai_queue_alert_minutes'] as $key)
        verify(isset(Policy::fields()[$key]),'New setting belongs to shared UI/runtime catalogue');
} finally {$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} queue efficiency checks; SQL rolled back\n";
