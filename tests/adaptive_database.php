<?php
if(PHP_SAPI!=='cli')exit(1);
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__,4).'/configuration.php';
require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{Database,BehaviorStore,Safety,Policy,Migrations};
use WHMCS\Database\Capsule;
$capsule=new Capsule();
$capsule->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,
    'password'=>$db_password,'charset'=>'utf8mb4','collation'=>'utf8mb4_unicode_ci','prefix'=>'']);
$capsule->setAsGlobal();$capsule->bootEloquent();
// Schema28 only adds settings; schema27 already has this fixture's physical metadata.
if((int)Database::getConfig('schema_version')<27||(int)Database::getConfig('schema_version')>Migrations::VERSION)throw new RuntimeException('Provision schema27 metadata first; this fixture never migrates');
$checks=0;
function check($value,$label){global $checks;if(!$value)throw new RuntimeException($label);$checks++;}
$db=Capsule::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)
    throw new RuntimeException('Production cycle still active; rerun after it completes');
$path=tempnam('/var/log','amsfb-fixture-');
$db->beginTransaction();
try {
    Database::setConfig('ai_whitelist_ips','');
    $stamp=date('d/M/Y:H:i:s O');
    check(BehaviorStore::eventTime('['.date('D M d H:i:s').'.123456 '.date('Y').'] [core:error]')===time(),'Apache error timestamp');
    check(abs(BehaviorStore::eventTime(date('M j H:i:s').' server sshd: fixture')-time())<=1,'Syslog real timestamp');
    check(BehaviorStore::eventTime('unknown timestamp')===null,'Unknown time never manufactured');
    $line='198.51.100.246 - - ['.$stamp.'] "GET /.env HTTP/1.1" 404 100 "-" "scanner"';
    file_put_contents($path,$line."\n");
    check(BehaviorStore::collect($path)['mode']==='initialized_at_eof','Initial EOF');
    file_put_contents($path,$line."\n",FILE_APPEND);
    check(BehaviorStore::collect($path)['events']===1,'One source event');
    $row=Capsule::table('mod_amssoft_fail2ban_rollups')->where('source_log',$path)->first();
    check($row->events===1||$row->events==='1','Rollup count');
    BehaviorStore::collect($path);
    check((int)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->value('events')===1,'Reread does not multiply');
    file_put_contents($path,$line,FILE_APPEND);
    check(BehaviorStore::collect($path)['events']===0,'Incomplete line ignored');
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->update(['processing_state'=>'review','validation_attempts'=>3]);
    file_put_contents($path,"\n",FILE_APPEND);
    check(BehaviorStore::collect($path)['events']===1,'Completed line once');
    $row=Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->first();
    check($row->processing_state==='review'&&(int)$row->validation_attempts===3,'New source event preserves technical review and validation budget');
    $s=['ip'=>'198.51.100.246','severity'=>'high','confidence'=>95,'evidence'=>[$line],'source_log'=>$path,
        'status'=>'pending','action'=>'ban','filter_name'=>'fixture-env','threat'=>'test','_pattern'=>$row->pattern,
        '_events'=>json_decode($row->samples,true),'_evidence_validated'=>true,'_native_validated'=>true];
    $id=Database::saveSuggestion($s);Database::recordDetections($id,$s);Database::recordDetections($id,$s);
    check(Capsule::table('mod_amssoft_fail2ban_detections')->where('suggestion_id',$id)->count()===2,'Different offsets count, reanalysis does not');
    $s['confidence']=98;$s['threat']='updated';check(Database::saveSuggestion($s)===$id,'Upsert identity');
    check(Database::getSuggestion($id)['threat']==='updated','Upsert refreshes evidence metadata');
    $other=$s;$other['_pattern']=hash('sha256','other-task-pattern');$other['action']='monitor';$other['threat']='benign task';
    $otherId=Database::saveSuggestion($other);
    check($otherId!==$id,'Different pattern receives independent suggestion');
    check(Database::getSuggestion($id)['classification']==='ban'&&Database::getSuggestion($id)['threat']==='updated','Benign task does not overwrite attack decision');
    check(Database::saveSuggestion($other)===$otherId,'Same alternate task still upserts idempotently');
    $attack=str_replace('198.51.100.246','2001:db8::246',$line);
    Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->update(['analyzed_revision'=>$row->revision,'processing_state'=>'processed']);
    file_put_contents($path,$attack."\n",FILE_APPEND);BehaviorStore::collect($path);
    $campaign=BehaviorStore::campaign($row->pattern);
    check($campaign['events']>=3&&$campaign['ips']>=2,'Slow campaign crosses peers');
    check((int)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->value('analyzed_revision')===(int)$row->revision,'Unclassified peer cannot authorize campaign revisitation');
    $peerRow=Capsule::table('mod_amssoft_fail2ban_rollups')->where('source_log',$path)->where('ip','2001:db8::246')->first();
    $peer=$s;$peer['ip']='2001:db8::246';$peer['evidence']=[$attack];$peer['_events']=json_decode($peerRow->samples,true);
    Database::recordDetections(Database::saveSuggestion($peer),$peer);
    BehaviorStore::revisitCampaigns([$row->pattern]);
    check((int)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->value('analyzed_revision')===0,'Validated campaign revisits earlier suspicious peer');
    $old=$line;file_put_contents($path,str_replace('/.env','/.git',$old)."\n");clearstatcache(true,$path);
    check(BehaviorStore::collect($path)['events']===1,'Same-inode truncation/anchor change');
    $normal=str_replace('/.env','/clientarea.php',$line);
    $bound=Safety::bindSuggestions([['ip'=>$s['ip'],'evidence'=>[$line]]],[$normal,$line]);
    check($bound[0]['evidence']===[$line]&&$bound[0]['_evidence_validated'],'Own cited attack, not first normal line');
    $bound=Safety::bindSuggestions([['ip'=>$s['ip'],'evidence'=>[$attack]]],[$line]);
    check(!$bound[0]['_evidence_validated'],'Cannot borrow another peer evidence');
    file_put_contents($path,str_repeat('x',70000)."\n".$attack."\n",FILE_APPEND);
    check(BehaviorStore::collect($path)['events']===1,'Oversized input skipped without losing following complete event');
    $cursor=json_decode(Database::getConfig('adaptive_cursor.'.md5($path)),true);
    check($cursor['offset']===filesize($path)&&!$cursor['draining'],'Bounded reader recovers at newline');
} finally {$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");unlink($path);}
echo "PASS: {$checks} adaptive database checks; SQL rolled back, fixture removed\n";
