<?php
namespace AMS\Fail2Ban {
final class Privileged {public static array $calls=[];public static function run(array $args):array{self::$calls[]=$args;throw new \RuntimeException('Unexpected real native operation');}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,Policy,Privileged,Router,Controllers\AIController};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');
$db->beginTransaction();$checks=0;
function pcCheck($value,$why){global $checks;if(!$value)throw new RuntimeException($why);$checks++;}
try{
    Database::setConfig('ai_auto_enabled','0');Database::setConfig('ai_mode','suggestion');
    $snapshot=Policy::snapshot();$version=$snapshot['version'];$stale=$snapshot['values'];
    Policy::save(['ai_auto_min_confidence'=>'99'],1,$version);
    $current=Database::getConfig('policy_version','0');
    pcCheck((int)$current===(int)$version+1,'Current form increments policy version');
    $stale['monitor_hours']='48';$stale['native_probe_groups']="env\ngit";
    $baseline=Policy::values();$auditCount=$db->table('mod_amssoft_fail2ban_logs')->count();
    foreach([$version,null,'',[],(int)$current,'0'.$current,'malformed'] as $expected){
        try{Policy::save($stale,1,$expected);pcCheck(false,'Stale/missing/malformed version accepted');}
        catch(InvalidArgumentException $e){pcCheck(str_contains($e->getMessage(),'Recarregue'),'Conflict gives reload guidance');}
        pcCheck(Policy::values()===$baseline,'Conflict leaves all policy values unchanged');
        pcCheck(Database::getConfig('policy_version','0')===$current,'Conflict never increments version');
        pcCheck($db->table('mod_amssoft_fail2ban_logs')->count()===$auditCount,'Conflict writes no audit or SQL policy');
        pcCheck(Privileged::$calls===[],'Conflict invokes no native effect');
        pcCheck((int)$db->selectOne("SELECT IS_USED_LOCK('amsfb_policy') AS owner")->owner===0,'Conflict releases policy lock');
    }
    Policy::save(['monitor_hours'=>'48'],0,$current);
    pcCheck(Database::getConfig('monitor_hours')==='48','Explicit-version partial CLI save works');
    pcCheck(Database::getConfig('ai_auto_min_confidence')==='99','Partial CLI save preserves concurrent setting');
    try{Policy::save(['monitor_hours'=>'24'],1,$current);pcCheck(false,'Frozen stale maintenance version accepted');}
    catch(InvalidArgumentException $e){pcCheck(true,'Frozen maintenance version rejects intervening change');}
    $_SESSION=['adminid'=>1];$controller=new AIController([],new Router([]));
    $save=new ReflectionMethod($controller,'persistSettings');
    $oldPrompt=Database::getConfig('ai_prompt');$oldProvider=Database::getConfig('ai_active_provider');
    try{$save->invoke($controller,['policy_version'=>$current,'ai_prompt'=>'stale fixture prompt']);pcCheck(false,'Settings stale version accepted');}
    catch(InvalidArgumentException $e){pcCheck(true,'Settings rejects stale version');}
    pcCheck(Database::getConfig('ai_prompt')===$oldPrompt&&Database::getConfig('ai_active_provider')===$oldProvider,'Settings rejects before provider/prompt SQL writes');
    pcCheck(Privileged::$calls===[],'Settings conflict performs no native operation');
    $expected=Database::getConfig('policy_version','0');
    $returned=$save->invoke($controller,['policy_version'=>$expected,'confirm_settings'=>'1','ai_prompt'=>'valid fixture prompt {logs}']);
    pcCheck($returned===Database::getConfig('policy_version','0')&&(int)$returned===(int)$expected+1,'Settings returns its committed version for next AJAX save');
    $again=$save->invoke($controller,['policy_version'=>$returned,'confirm_settings'=>'1','ai_prompt'=>'second valid fixture prompt {logs}']);
    pcCheck((int)$again===(int)$returned+1,'Second AJAX save can use returned version');
}finally{$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} policy concurrency/version checks; SQL rollback and no real native/API effects\n";
}
