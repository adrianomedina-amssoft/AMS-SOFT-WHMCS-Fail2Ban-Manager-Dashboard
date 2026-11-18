<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
/** Only connection-local TEMPORARY tables shadow module tables; never migrates or writes real tables. */
class Database {
 public static array $cfg=['schema_version'=>'37'];
 public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}
 public static function incrementConfig($k,$n=1){self::$cfg[$k]=(int)(self::$cfg[$k]??0)+$n;}
}
class Policy {
 public static function number($k){return ['ai_behavior_enabled'=>1,'ai_behavior_require_repetition'=>0,'ai_behavior_min_events'=>3,'ai_behavior_min_ips'=>2,'ai_behavior_hours'=>24,'ai_analysis_recent_minutes'=>30,'ai_auto_min_confidence'=>90,'ai_campaign_revisit_minutes'=>240][$k];}
}
require '/var/www/html/whmcs/configuration.php';require '/var/www/html/whmcs/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
$created=[];$n=0;function dbRevisitCheck($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
$roll='mod_amssoft_fail2ban_rollups';$sug='mod_amssoft_fail2ban_ai_suggestions';$det='mod_amssoft_fail2ban_detections';$link=EvidenceLinks::TABLE;
try{
 foreach([
 $roll=>'id CHAR(64) PRIMARY KEY, ip VARCHAR(45), source_log VARCHAR(255), pattern CHAR(64), family_key VARCHAR(90), bucket DATETIME, last_event_at DATETIME, samples LONGTEXT, revision INT, analyzed_revision INT, processing_state VARCHAR(32), retry_at DATETIME NULL, blocked_confirmed_at DATETIME NULL, blocked_until_check_at DATETIME NULL, decision_state VARCHAR(32) NULL, attempts INT DEFAULT 0, validation_attempts INT DEFAULT 0, campaign_signature CHAR(64) NULL, campaign_members TEXT NULL, last_revisit_at DATETIME NULL',
 $sug=>'id INT PRIMARY KEY, ip VARCHAR(45), source_log VARCHAR(255), pattern CHAR(64), task_id CHAR(64), classification VARCHAR(20), status VARCHAR(20), confidence INT',
 $det=>'fingerprint CHAR(64) PRIMARY KEY, ip VARCHAR(45), source_log VARCHAR(255), pattern CHAR(64), family_key VARCHAR(90), validation_state VARCHAR(20), confidence INT, detected_at DATETIME',
 $link=>'fingerprint CHAR(64), suggestion_id INT, validation_state VARCHAR(20), confidence INT',
 ] as $table=>$ddl){$db->statement('CREATE TEMPORARY TABLE `'.$table.'` ('.$ddl.') ENGINE=InnoDB');$created[]=$table;}
 $db->beginTransaction();$now=time();$source='/var/log/apache2/access.log';$pattern=hash('sha256','revisit-fixture');$rows=[];
 foreach(['fresh'=>60,'old_same_ip'=>51685,'other_task'=>70,'held'=>80,'review'=>90,'other_peer'=>100] as $name=>$age){
  $ip=$name==='other_peer'?'198.51.100.78':'198.51.100.77';$stamp=$now-$age;
  $line=$ip.' - - ['.date('d/M/Y:H:i:s O',$stamp).'] "GET /boaform/adminformLogout//boaform/admin/login.asp HTTP/1.0" 404 10 "-" "-"';
  $r=['id'=>hash('sha256',$name),'ip'=>$ip,'source_log'=>$source,'pattern'=>$pattern,'family_key'=>'test-family','bucket'=>date('Y-m-d H:i:s',(int)(floor($stamp/600)*600)),
   'last_event_at'=>date('Y-m-d H:i:s',$stamp),'samples'=>json_encode([['line'=>$line,'time'=>$stamp]]),'revision'=>1,'analyzed_revision'=>1,
   'processing_state'=>$name==='review'?'review':'processed','attempts'=>0,'validation_attempts'=>0,'campaign_signature'=>null,'campaign_members'=>'[]'];
  if($name==='held'){$r['blocked_confirmed_at']=date('Y-m-d H:i:s',$now-5);$r['blocked_until_check_at']=date('Y-m-d H:i:s',$now+300);}
  C::table($roll)->insert($r);$rows[$name]=$r;
 }
 $id=0;foreach(['fresh','held','review','other_peer'] as $name){
  $r=$rows[$name];$id++;$s=['id'=>$id,'ip'=>$r['ip'],'source_log'=>$source,'pattern'=>$pattern,'task_id'=>$r['id'],'classification'=>'ban','status'=>$name==='other_peer'?'auto_executed':'pending','confidence'=>99];C::table($sug)->insert($s);
  $fp=hash('sha256','proof'.$id);C::table($det)->insert(['fingerprint'=>$fp,'ip'=>$r['ip'],'source_log'=>$source,'pattern'=>$pattern,'family_key'=>'test-family','validation_state'=>'valid','confidence'=>99,'detected_at'=>$r['last_event_at']]);
  C::table($link)->insert(['fingerprint'=>$fp,'suggestion_id'=>$id,'validation_state'=>'valid','confidence'=>99]);
 }
 $row=fn($name)=>(array)C::table($roll)->where('id',$rows[$name]['id'])->first();
 BehaviorStore::revisitCampaigns([$pattern]);
 dbRevisitCheck($row('fresh')['analyzed_revision']===0&&$row('fresh')['processing_state']==='pending','Fresh own task reopened with consistent state');
 foreach(['old_same_ip','other_task','held','review','other_peer'] as $name)dbRevisitCheck($row($name)['analyzed_revision']===1,'No borrowed proof or protected workflow: '.$name);
 dbRevisitCheck(Database::$cfg['ai_queue_entries_total']===1,'Count one effective update');
 BehaviorStore::revisitCampaigns([$pattern]);dbRevisitCheck(Database::$cfg['ai_queue_entries_total']===1,'Already pending does not increment');
 $reset=function($values=[])use($roll,$rows){C::table($roll)->where('id',$rows['fresh']['id'])->update(array_replace(['analyzed_revision'=>1,'processing_state'=>'processed','campaign_signature'=>null,'campaign_members'=>'[]','last_revisit_at'=>null,'retry_at'=>null,'attempts'=>0,'validation_attempts'=>0],$values));};
 $reset(['retry_at'=>date('Y-m-d H:i:s',$now+300)]);BehaviorStore::revisitCampaigns([$pattern]);dbRevisitCheck($row('fresh')['analyzed_revision']===1,'Backoff preserved');
 $reset(['attempts'=>2,'validation_attempts'=>2]);BehaviorStore::revisitCampaigns([$pattern]);dbRevisitCheck($row('fresh')['processing_state']==='retry'&&$row('fresh')['attempts']===2&&$row('fresh')['validation_attempts']===2,'Due retry retains budgets');
 $reset(['samples'=>$rows['old_same_ip']['samples']]);BehaviorStore::revisitCampaigns([$pattern]);dbRevisitCheck($row('fresh')['analyzed_revision']===1,'Fresh metadata cannot hide old samples');
 $reset(['samples'=>$rows['fresh']['samples']]);C::table($sug)->where('id',1)->update(['task_id'=>$rows['other_task']['id']]);BehaviorStore::revisitCampaigns([$pattern]);dbRevisitCheck($row('fresh')['analyzed_revision']===1,'Different task cannot authorize current row');
 C::table($sug)->where('id',1)->update(['task_id'=>$rows['fresh']['id']]);C::table($link)->where('suggestion_id',1)->update(['validation_state'=>'unknown']);BehaviorStore::revisitCampaigns([$pattern]);dbRevisitCheck($row('fresh')['analyzed_revision']===1,'Unvalidated association cannot reopen');
 C::table($link)->where('suggestion_id',1)->update(['validation_state'=>'valid']);$reset(['last_revisit_at'=>date('Y-m-d H:i:s',$now-60)]);BehaviorStore::revisitCampaigns([$pattern]);dbRevisitCheck($row('fresh')['analyzed_revision']===1,'Cooldown preserved');
 echo "PASS: {$n} campaign task-bound proof, freshness, counters and workflow checks; MySQL TEMPORARY tables only, no provider/native\n";
}finally{
 if($db->transactionLevel()>0)$db->rollBack();
 foreach(array_reverse($created) as $table)$db->statement('DROP TEMPORARY TABLE IF EXISTS `'.$table.'`');
}
