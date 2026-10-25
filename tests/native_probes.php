<?php
namespace AMS\Fail2Ban {
class AutoBanEngine {public static function loadWhitelist():array{return ['198.51.100.245'];}}
class Privileged {public static array $calls=[];public static bool $failNext=false;
 public static function run(array $a):array{if($a[0]!=='sync-sensitive-probes')throw new \RuntimeException('Unexpected native/API operation');
  self::$calls[]=json_decode(file_get_contents($a[1]),true);$fail=self::$failNext;self::$failNext=false;return ['success'=>!$fail];}
}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{Database,Policy,NativeProbes,Privileged};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy; retry');
$db->beginTransaction();$checks=0;function check($v,$why){global $checks;if(!$v)throw new RuntimeException($why);$checks++;}
try{
 Database::setConfig('schema_version','26');Database::setConfig('ai_auto_enabled','0');Database::setConfig('ai_mode','suggestion');
 foreach(NativeProbes::KEYS as $k)Database::setConfig($k,(string)Policy::fields()[$k][2]);
 $v=Policy::values();check(!NativeProbes::changed($v,$v),'Unchanged policy has native delta');
 foreach(['phpunit','debug','db_admin','exchange_probe','gpon_probe'] as $group){$next=Policy::validate(['native_probe_groups'=>$group],$v);check($next['native_probe_groups']===$group,'New group unavailable in UI validation');}
 foreach(['.*','env git ;reboot','/etc/passwd',''] as $bad){try{Policy::validate(['native_probe_groups'=>$bad],$v);check(false,'Bad group accepted');}catch(InvalidArgumentException $e){check(true,'Invalid group');}}
 Policy::save(['native_probe_maxretry'=>'2'],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));
 check(Database::getConfig('native_probe_maxretry')==='2'&&end(Privileged::$calls)['maxretry']===2,'UI save not applied natively');
 check(end(Privileged::$calls)['whitelist']===['198.51.100.245'],'Whitelist absent from fixed payload');
 check(Database::getConfig('ai_auto_enabled')==='0','Native policy required/enabled paid IA');
 $before=count(Privileged::$calls);Policy::save([],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));check(count(Privileged::$calls)===$before,'Unchanged policy rewrote native filter');
 Privileged::$failNext=true;
 try{Policy::save(['native_probe_maxretry'=>'3'],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));check(false,'Native refusal accepted');}catch(RuntimeException $e){check(str_contains($e->getMessage(),'não confirmada'),'Native refusal hidden');}
 check(Database::getConfig('native_probe_maxretry')==='2'&&end(Privileged::$calls)['maxretry']===2,'Native refusal not compensated');
 $failWrite=true;$db->setEventDispatcher(new \Illuminate\Events\Dispatcher());
 $db->listen(function($q)use(&$failWrite){if($failWrite&&str_starts_with($q->sql,'insert into `mod_amssoft_fail2ban_logs`')&&in_array('policy_changed',$q->bindings,true)){$failWrite=false;throw new RuntimeException('Fixture SQL failure');}});
 try{Policy::save(['native_probe_maxretry'=>'4'],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));check(false,'SQL failure accepted');}catch(RuntimeException $e){check($e->getMessage()==='Fixture SQL failure','SQL failure lost');}
 check(Database::getConfig('native_probe_maxretry')==='2'&&end(Privileged::$calls)['maxretry']===2,'SQL rollback not compensated natively');
 Policy::save(['native_probe_enabled'=>'0'],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));check(end(Privileged::$calls)['enabled']===0,'Disable did not reach detector-only bridge');
 check(array_keys(end(Privileged::$calls))===['enabled','groups','maxretry','findtime','bantime','whitelist'],'Native manifest broadened');
}finally{$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} native policy UI/rollback checks; SQL rolled back, fake native, no provider\n";
}
