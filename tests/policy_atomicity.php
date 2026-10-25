<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
// Exercise the production Policy with the real SQL adapter. Native effects stay
// in memory, and the outer transaction is always rolled back.
final class NativePolicy {
    public static int $calls=0;
    public static bool $throwNext=false;
    public static function sync(): bool {
        self::$calls++;
        if(self::$throwNext){self::$throwNext=false;throw new \RuntimeException('Fixture compensation unavailable');}
        return true;
    }
}
final class Privileged {
    public static string $duration='3600';
    public static array $calls=[];
    public static bool $failRestore=false;
    public static function run(array $args): array {
        self::$calls[]=$args;
        if($args[0]!=='ensure-ai-jail')throw new \RuntimeException('Unexpected native operation');
        if(self::$failRestore && $args[1]==='3600')throw new \RuntimeException('Fixture jail restoration unavailable');
        self::$duration=$args[1];return ['success'=>true];
    }
}
final class AIAnalyzer {
    public static function getActiveConfig(): array {return ['api_key'=>'fixture-only'];}
}
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__,4).'/configuration.php';
require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule;
$c=new Capsule();$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,
    'password'=>$db_password,'charset'=>'utf8mb4','collation'=>'utf8mb4_unicode_ci','prefix'=>'']);
$c->setAsGlobal();$c->bootEloquent();$db=Capsule::connection();$checks=0;
function check($v,$label){global $checks;if(!$v)throw new \RuntimeException($label);$checks++;}
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)
    throw new \RuntimeException('Production cycle still active; rerun after it completes');
$db->beginTransaction();
try {
    Database::setConfig('ai_auto_enabled','1');Database::setConfig('ai_mode','threshold');
    Database::setConfig('global_bantime','3600');
    $oldVersion=Database::getConfig('policy_version','0');
    $failWrite=false;$failCompensation=false;
    $db->setEventDispatcher(new \Illuminate\Events\Dispatcher());
    $db->listen(function($query)use(&$failWrite,&$failCompensation){
        if($failWrite && str_starts_with($query->sql,'insert into `mod_amssoft_fail2ban_logs`')
            && in_array('policy_changed',$query->bindings,true)) {
            $failWrite=false;
            NativePolicy::$throwNext=$failCompensation;
            throw new \RuntimeException('Fixture policy audit write failed');
        }
    });
    $failWrite=true;
    try {Policy::save(['global_bantime'=>'7200'],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));throw new \RuntimeException('SQL failure accepted');}
    catch(\RuntimeException $e){check($e->getMessage()==='Fixture policy audit write failed','Original SQL failure propagated');}
    check(Database::getConfig('global_bantime')==='3600','SQL duration restored after failed save');
    check(Database::getConfig('policy_version','0')===$oldVersion,'Policy version restored');
    check(Privileged::$duration==='3600','Native duration reconciled after failed save');
    check(Privileged::$calls===[['ensure-ai-jail','7200'],['ensure-ai-jail','3600']],'Only changed jail duration compensated');
    check((int)$db->selectOne("SELECT IS_USED_LOCK('amsfb_policy') AS owner")->owner===0,'Policy lock released after rollback');
    $failWrite=true;$failCompensation=true;
    try {Policy::save(['global_bantime'=>'7200'],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));throw new \RuntimeException('Compensation failure accepted');}
    catch(\RuntimeException $e){
        check(str_contains($e->getMessage(),'reconciliação nativa pendente'),'Compensation failure reported');
        check($e->getPrevious()?->getMessage()==='Fixture policy audit write failed','Original failure retained as cause');
    }
    check($db->table('mod_amssoft_fail2ban_logs')->where('action','policy_sync_failed')->exists(),'Compensation failure audited');
    check(Privileged::$duration==='3600','Jail restoration still attempted when whitelist restoration throws');
    check((int)$db->selectOne("SELECT IS_USED_LOCK('amsfb_policy') AS owner")->owner===0,'Policy lock released after compensation failure');
    $failCompensation=false;$failWrite=true;Privileged::$failRestore=true;
    try {Policy::save(['global_bantime'=>'7200'],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));throw new \RuntimeException('Jail compensation failure accepted');}
    catch(\RuntimeException $e){
        check(str_contains($e->getMessage(),'reconciliação nativa pendente'),'Jail compensation exception reported');
        check($e->getPrevious()?->getMessage()==='Fixture policy audit write failed','SQL cause retained after jail compensation failure');
    }
    check(Database::getConfig('global_bantime')==='3600','Failed jail compensation never commits SQL policy');
    check(Privileged::$duration==='7200','Unrestored native state is reported rather than called successful');
    Privileged::$failRestore=false;Privileged::$duration='3600';
    $c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,
        'password'=>$db_password,'charset'=>'utf8mb4'],'contender');
    $other=$c->getConnection('contender');
    check((int)$other->selectOne("SELECT GET_LOCK('amsfb_policy',0) AS acquired")->acquired===1,'Contender acquired policy lock');
    $callsBefore=count(Privileged::$calls);$syncsBefore=NativePolicy::$calls;
    try {
        try {Policy::save(['global_bantime'=>'7200'],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));throw new \RuntimeException('Contended save accepted');}
        catch(\RuntimeException $e){check(str_contains($e->getMessage(),'Configuração em uso'),'Contended save refused');}
        check(count(Privileged::$calls)===$callsBefore && NativePolicy::$calls===$syncsBefore,'Contention performs no native writes');
        check(Database::getConfig('global_bantime')==='3600','Contention performs no SQL writes');
    } finally {$other->selectOne("SELECT RELEASE_LOCK('amsfb_policy')");}
    Policy::save(['global_bantime'=>'7200'],1,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));
    check(Database::getConfig('global_bantime')==='7200' && Privileged::$duration==='7200','Successful save agrees with native state');
} finally {$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} policy atomicity checks; real SQL rollback, native effects mocked\n";
