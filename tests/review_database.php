<?php
if(PHP_SAPI!=='cli')exit(1);
$whmcs=getenv('AMSFB_TEST_WHMCS_ROOT')?:dirname(__DIR__,4);
require $whmcs.'/configuration.php';require $whmcs.'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule;
use AMS\Fail2Ban\{Database,BehaviorStore,AIAnalyzer,CycleBudget};
$c=new Capsule();$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
$db=Capsule::connection();$checks=0;function check($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy; retry after completion');
try {
 $db->beginTransaction();
 Capsule::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>Capsule::raw('revision')]);
 foreach(['ai_review_auto_recovery_enabled'=>'1','ai_review_recovery_limit'=>'1','ai_review_recovery_cursor'=>'null'] as $k=>$v)Database::setConfig($k,$v);
 $prefix=bin2hex(random_bytes(16));$bucket=date('Y-m-d H:i:s',time()-600);$future=date('Y-m-d H:i:s',time()+600);
 for($i=0;$i<101;$i++) {
  $ip='198.18.1.'.($i+1);$id=$prefix.sprintf('%032x',$i);
  $event=['id'=>hash('sha256',$id),'ip'=>$ip,'pattern'=>'review_fixture','time'=>time(),'line'=>$ip.' fixture evidence'];
  Capsule::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$id,'ip'=>$ip,'source_log'=>'/var/log/review-fixture','pattern'=>'review_fixture','bucket'=>$bucket,'events'=>1,'revision'=>1,'analyzed_revision'=>0,
   'samples'=>$i<100?'[]':json_encode([$event]),'processing_state'=>'review','failure_code'=>'filter_positive','validation_generation'=>'older-correction',
   'attempts'=>7,'validation_attempts'=>3,'total_attempts'=>7,'total_validation_attempts'=>3,'retry_at'=>$future]);
 }
 $last=$id;$row=fn()=>Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$last)->first();
 check(BehaviorStore::recoverReviews()===0,'First scan inspects only 100 unprovable reviews');
 $cursor=json_decode(Database::getConfig('ai_review_recovery_cursor'),true);
 check($cursor['id']===$prefix.sprintf('%032x',99),'Cursor advances past unprovable tasks with equal bucket');
 check(BehaviorStore::recoverReviews()===1,'Second scan reaches task 101 with proof');
 check($row()->processing_state==='retry'&&$row()->retry_at===$future,'Recovery preserves backoff');
 check((int)$row()->total_attempts===7&&(int)$row()->total_validation_attempts===3,'Totals preserved');
 check((int)$row()->recovery_rounds===1&&$row()->recovery_generation===AIAnalyzer::RECOVERY_GENERATION,'One round in current generation');
 check(Database::getConfig('ai_review_recovery_cursor')==='null','End of scan wraps cursor');
 Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$last)->update(['processing_state'=>'review','validation_generation'=>AIAnalyzer::RECOVERY_GENERATION]);
 BehaviorStore::recoverReviews();check(BehaviorStore::recoverReviews()===0,'Current generation cannot recover again at limit one');
 Database::setConfig('ai_review_recovery_limit','2');BehaviorStore::recoverReviews();check(BehaviorStore::recoverReviews()===1,'Configured second round remains reachable after unprovable prefix');
 check((int)$row()->recovery_rounds===2,'Configured round counted');
 Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$last)->update(['processing_state'=>'review']);
 BehaviorStore::recoverReviews();check(BehaviorStore::recoverReviews()===0,'Two round limit remains finite');
 Database::setConfig('ai_review_auto_recovery_enabled','0');$before=Database::getConfig('ai_review_recovery_cursor');
 check(BehaviorStore::recoverReviews()===0&&Database::getConfig('ai_review_recovery_cursor')===$before,'Disabled recovery does not move cursor');
 Database::setConfig('ai_review_auto_recovery_enabled','1');Database::setConfig('ai_review_recovery_cursor',json_encode(['generation'=>'old','bucket'=>date('Y-m-d H:i:s',time()+600),'id'=>str_repeat('f',64)]));
 BehaviorStore::recoverReviews();check(json_decode(Database::getConfig('ai_review_recovery_cursor'),true)['generation']===AIAnalyzer::RECOVERY_GENERATION,'Cursor from older generation resets');
 $before=Database::getConfig('ai_review_recovery_cursor');CycleBudget::begin(0);check(BehaviorStore::recoverReviews()===0&&Database::getConfig('ai_review_recovery_cursor')===$before,'No budget does not skip uninspected work');
}finally{CycleBudget::end();if($db->transactionLevel()>0)$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} review database checks; SQL rolled back, no DDL/API/firewall\n";
