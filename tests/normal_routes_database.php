<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Privileged {
    public static array $routes=[], $calls=[];
    public static function run(array $args): array {
        self::$calls[]=$args[0];
        if($args[0]!=='sync-normal-paths')throw new \RuntimeException('Unexpected native effect');
        self::$routes=json_decode(file_get_contents($args[1]),true,512,JSON_THROW_ON_ERROR)['paths'];
        return ['success'=>true];
    }
}
class NativePolicy {
    public static bool $failNext=false;
    public static function sync(): bool {
        NormalRoutes::sync();
        if(self::$failNext){self::$failNext=false;return false;}
        return true;
    }
}
require dirname(__DIR__,4).'/configuration.php';
require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
$c=new C();$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,
    'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
$db=C::connection();$checks=0;
function nr($v,$why){global $checks;if(!$v)throw new \RuntimeException($why);$checks++;}
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new \RuntimeException('Cycle busy');
$db->beginTransaction();
try {
    Database::setConfig('schema_version','34');
    Database::setConfig('ai_auto_enabled','0');Database::setConfig('ai_mode','suggestion');
    Database::setConfig('ai_non_offensive_paths',"/\n/graylog");
    NormalRoutes::sync();Privileged::$calls=[];$version=Database::getConfig('policy_version','0');
    $fail=false;$db->setEventDispatcher(new \Illuminate\Events\Dispatcher());
    $db->listen(function($q)use(&$fail){
        if($fail&&str_starts_with($q->sql,'insert into ')&&str_contains($q->sql,'mod_amssoft_fail2ban_logs')&&in_array('policy_changed',$q->bindings,true)){
            $fail=false;throw new \RuntimeException('Fixture SQL failure');
        }
    });
    $fail=true;
    try{Policy::save(['ai_non_offensive_paths'=>"/\n/graylog\n/new"],1,$version);nr(false,'SQL failure accepted');}
    catch(\RuntimeException $e){nr($e->getMessage()==='Fixture SQL failure','Original SQL failure');}
    nr(Database::getConfig('ai_non_offensive_paths')==="/\n/graylog",'SQL rollback');
    nr(Privileged::$routes===['/','/graylog']&&count(Privileged::$calls)===2,'Native compensation');
    nr(Database::getConfig('policy_version','0')===$version,'Version preserved');
    Policy::save(['ai_non_offensive_paths'=>"/\n/graylog\n/new"],1,$version);
    nr(Privileged::$routes===['/','/graylog','/new'],'Successful native sync');
    nr(Database::getConfig('ai_non_offensive_paths')==="/\n/graylog\n/new",'Successful SQL sync');
    $_SESSION=['adminid'=>1];
    $controller=new Controllers\AIController([],new Router([]));$save=new \ReflectionMethod($controller,'persistSettings');
    NativePolicy::$failNext=true;$version=Database::getConfig('policy_version','0');
    try{$save->invoke($controller,['policy_version'=>$version,'confirm_settings'=>'1',
        'ai_whitelist_ips'=>'203.0.113.20']);nr(false,'Outer failure accepted');}
    catch(\RuntimeException $e){nr($e->getMessage()==='Whitelist nativa não sincronizada.','Outer failure reported');}
    nr(Database::getConfig('ai_non_offensive_paths')==="/\n/graylog\n/new",'Outer SQL rollback');
    nr(Privileged::$routes===['/','/graylog','/new'],'Outer native compensation');
    nr(Database::getConfig('policy_version','0')===$version,'Outer version preserved');
    nr((int)$db->selectOne("SELECT IS_USED_LOCK('amsfb_policy') AS owner")->owner===0,'Lock released');
    nr(array_diff(Privileged::$calls,['sync-normal-paths'])===[],'No daemon, ban or API calls');
    $plain="Análise <HOST> e \"aspas\" {logs}\nInstrução posterior.";
    $save->invoke($controller,['policy_version'=>$version,'confirm_settings'=>'1','ai_prompt_b64'=>base64_encode($plain)]);
    nr(Database::getConfig('ai_prompt')===$plain,'UTF-8/HTML roundtrip stores plain text');
    $version=Database::getConfig('policy_version','0');$calls=Privileged::$calls;
    foreach(['not base64!','eA==','eyBsb2dzIH0='] as $bad){
        try{$save->invoke($controller,['policy_version'=>$version,'confirm_settings'=>'1','ai_prompt_b64'=>$bad]);nr(false,'Bad transport accepted');}
        catch(\InvalidArgumentException $e){nr(true,'Bad transport or placeholder rejected');}
    }
    nr(Database::getConfig('ai_prompt')===$plain&&Database::getConfig('policy_version','0')===$version,'Invalid transport preserves saved state');
    nr(Privileged::$calls===$calls,'Invalid transport has no native effects');
    C::table(AnalysisWork::BATCH_TABLE)->where('status','pending')->update(['status'=>'complete']);
    $tasks=C::table('mod_amssoft_fail2ban_rollups')->count();
    $checkpoint=AnalysisWork::saveBatch([['id'=>hash('sha256','prompt-contract-fixture')]],[],[],[]);
    nr(AnalysisWork::nextBatch()['id']===$checkpoint,'Current checkpoint reusable before change');
    Database::setConfig('ai_prompt','new analysis contract {logs}');
    nr(AnalysisWork::nextBatch()===null,'Old checkpoint not reused after prompt change');
    nr(C::table(AnalysisWork::BATCH_TABLE)->where('id',$checkpoint)->value('status')==='invalidated','Checkpoint retained as invalidated');
    nr(C::table('mod_amssoft_fail2ban_rollups')->count()===$tasks,'Task history preserved');
} finally {$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} catalogue atomicity checks; real SQL rollback, native effects mocked\n";
