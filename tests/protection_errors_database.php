<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
// Real policy transactions against connection-local temporary tables only.
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
    public static bool $failSync=false;
    public static function run(array $args): array {
        self::$calls[]=$args;
        if(in_array($args[0],['sync-normal-paths','sync-sensitive-probes'],true))return ['success'=>!self::$failSync];
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
$app=$argv[1]??dirname(__DIR__,4);
require $app.'/configuration.php';
require $app.'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule;
$c=new Capsule();$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,
    'password'=>$db_password,'charset'=>'utf8mb4','collation'=>'utf8mb4_unicode_ci','prefix'=>'']);
$c->setAsGlobal();$c->bootEloquent();$db=Capsule::connection();$checks=0;
function check($v,$label){global $checks;if(!$v)throw new \RuntimeException($label);$checks++;}
$created=[];
foreach($db->select("SHOW TABLES LIKE 'mod_amssoft_fail2ban_%'") as $row){
    $table=array_values((array)$row)[0];if(!preg_match('/^mod_amssoft_fail2ban_[a-z_]+$/D',$table))throw new \RuntimeException('Unknown table');
    $ddl=array_values((array)$db->selectOne('SHOW CREATE TABLE '.$table))[1];
    $db->statement(preg_replace('/^CREATE TABLE /','CREATE TEMPORARY TABLE ',$ddl,1));$created[]=$table;
}
$db->beginTransaction();
try {
    foreach(Policy::fields() as $key=>$field)Database::setConfig($key,(string)$field[2]);
    Database::setConfig('schema_version','37');Database::setConfig('ai_confirmed_auto','1');
    Database::setConfig('ai_auto_enabled','1');Database::setConfig('ai_mode','threshold');
    Database::setConfig('global_bantime','3600');
    $oldVersion=Database::getConfig('policy_version','0');
    $failWrite=false;$failCompensation=false;$failAudit=false;
    $db->setEventDispatcher(new \Illuminate\Events\Dispatcher());
    $db->listen(function($query)use(&$failWrite,&$failCompensation,&$failAudit){
        if($failAudit&&str_starts_with($query->sql,'insert into `mod_amssoft_fail2ban_logs`')&&in_array('policy_sync_failed',$query->bindings,true))
            throw new \RuntimeException('private fixture audit SQL');
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
        check($e instanceof ProtectionFailure,'Pending reconciliation is a known public failure');
        $public=new \ReflectionMethod(Controllers\PolicyController::class,'publicError');
        check($public->invoke(null,$e)===$e->getMessage(),'Controller must not hide pending reconciliation');
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
    // Secondary audit failure must not mask pending native reconciliation.
    $failAudit=true;Privileged::$failSync=true;ini_set('error_log','/dev/null');
    $version=Database::getConfig('policy_version');$before=Policy::values();
    foreach([['ai_non_offensive_paths'=>"/\n/index.php\n/fixture-route"],['native_probe_maxretry'=>'2']] as $input){
        try{Policy::save($input,1,$version);throw new \LogicException('Failed sync accepted');}
        catch(ProtectionFailure $e){
            check(in_array($e->reason,['routes_reconciliation','probes_reconciliation'],true),'Wrong reconciliation reason');
            $message=$public->invoke(null,$e);
            check(str_contains($message,'pendente')&&!str_contains($message,'private'),'Safe actionable reconciliation message lost');
            check($e->getPrevious() instanceof ProtectionFailure,'Original failure retained privately');
        }
        check(Policy::values()===$before&&Database::getConfig('policy_version')===$version,'Sync refusal changed policy');
    }
} finally {$db->rollBack();foreach(array_reverse($created) as $table)$db->statement('DROP TEMPORARY TABLE IF EXISTS '.$table);}
echo "PASS: {$checks} protection rollback/public-error checks; temporary SQL, native effects mocked\n";
