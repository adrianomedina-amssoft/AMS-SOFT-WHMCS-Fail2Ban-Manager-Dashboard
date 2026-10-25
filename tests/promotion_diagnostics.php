<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
// Memory-only collaborators: no SQL, API, configuration writes or host bans.
class Database {
    public static array $cfg=[];
    public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}
    public static function setConfig($k,$v){self::$cfg[$k]=$v;}
    public static function incrementConfig($k){return self::$cfg[$k]=(int)(self::$cfg[$k]??0)+1;}
    public static function logEvent(...$a){}
}
class AIAnalyzer { public const RECOVERY_GENERATION='fixture'; }
class JailConfig { public function __construct(...$a){} }
class Fail2BanClient {
    public static array $jails=[];public int $bans=0;public bool $effective=false,$banOk=true;
    public function getJails(){return self::$jails;}
    public function hasEffectiveBan(...$a){return $this->effective;}
    public function banIP(...$a){$this->bans++;return $this->banOk;}
}
class LogLock {
    public static bool $busy=false;
    public static function acquire($p){return ['fp'=>self::$busy?null:fopen('php://temp','r+')];}
}
class Privileged {
    public static string $source=__FILE__,$filter='amsfb-fixture';
    public static function run($a){return ['success'=>true,'jails'=>['amsfb-fixture'=>['filter'=>self::$filter,'logpath'=>self::$source,'enabled'=>'true']]];}
}
class FilterManager {
    public static bool $exists=false,$jail=false,$valid=true,$install=true,$loaded=true,$reload=true;
    public static array $settings=[];
    public function __construct(...$a){}
    public function filterExists($n){return self::$exists;}
    public function findSimilarFilter($r){return null;}
    public function createFilter(...$a){return self::$install;}
    public function lastDiagnostic(){return ['code'=>'filter_install','error'=>'Injected install failure'];}
    public function filterDiagnostic(...$a){return ['success'=>self::$valid,'code'=>'filter_positive','error'=>'Injected missing positive'];}
    public function loadedFilterDiagnostic(...$a){return ['success'=>self::$loaded,'code'=>'loaded_source_mismatch','error'=>'Injected loaded mismatch'];}
    public function jailExists($n){return self::$jail;}
    public static function getAllowedLogs(){return [__FILE__];}
    public function detectLogPathSafe(...$a){return null;}
    public function createJailForFilter($j,$f,$s){self::$settings=$s;self::$jail=true;Fail2BanClient::$jails=[$j];return true;}
    public function reloadJail($j){return self::$reload;}
    public function removeFilter($n){return true;}
}
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__).'/lib/Safety.php';require dirname(__DIR__).'/lib/Policy.php';require dirname(__DIR__).'/lib/AutoBanEngine.php';
$checks=0;function check($v,$m){global $checks;if(!$v)throw new \RuntimeException($m);$checks++;}
function resetFixture(){
    Database::$cfg=['ai_auto_jails_created_date'=>date('Y-m-d'),'ai_auto_jails_created_today'=>'0','ai_new_jail_findtime'=>'900','ai_new_jail_maxretry'=>'7'];
    FilterManager::$exists=FilterManager::$jail=false;FilterManager::$valid=FilterManager::$install=FilterManager::$loaded=FilterManager::$reload=true;
    FilterManager::$settings=[];Fail2BanClient::$jails=[];Privileged::$source=__FILE__;Privileged::$filter='amsfb-fixture';LogLock::$busy=false;
}
$client=new Fail2BanClient();$engine=new AutoBanEngine(new AIAnalyzer(),$client);
$method=new \ReflectionMethod(AutoBanEngine::class,'promotionResult');$method->setAccessible(true);
$suggestion=['ip'=>'203.0.113.7','filter_name'=>'fixture','failregex'=>'^<HOST> attack$','evidence'=>['fixture'],'source_log'=>__FILE__];
$run=fn($ban=false)=>$method->invoke($engine,$suggestion,null,$ban);
resetFixture();$result=$run();check($result['success']&&!$result['banned'],'Promotion without implicit ban');
check(FilterManager::$settings['findtime']==='900'&&FilterManager::$settings['maxretry']==='7','New jail uses UI values');
check($client->bans===0,'Promotion does not ban related peers');
check(json_decode(Database::$cfg['ai_last_promotion_result'],true)['code']==='ready','Structured result persisted');
resetFixture();Database::$cfg['ai_auto_jails_created_today']='5';check($run()['code']==='daily_limit','Daily limit explicit');
resetFixture();LogLock::$busy=true;check($run()['code']==='lock_busy','Busy lock explicit');
resetFixture();FilterManager::$install=false;check($run()['stage']==='install','Install refusal explicit');
resetFixture();FilterManager::$valid=false;check($run()['code']==='filter_positive','Validation code preserved');
resetFixture();FilterManager::$exists=FilterManager::$jail=true;Fail2BanClient::$jails=['amsfb-fixture'];Privileged::$source='/nonexistent';
check($run()['code']==='source_mismatch','Other source cannot reuse filter');
resetFixture();FilterManager::$exists=FilterManager::$jail=true;check($run()['code']==='jail_inactive','Inactive jail not reenabled');
resetFixture();FilterManager::$exists=FilterManager::$jail=true;Fail2BanClient::$jails=['amsfb-fixture'];Privileged::$filter='amsfb-other';
check($run()['code']==='filter_mismatch','Effective filter mismatch explicit');
resetFixture();FilterManager::$exists=FilterManager::$jail=true;Fail2BanClient::$jails=['amsfb-fixture'];FilterManager::$loaded=false;
check($run()['stage']==='loaded_validation','Loaded mismatch refused independently of disk');
resetFixture();FilterManager::$reload=false;check($run()['code']==='reload_failed','Reload refusal explicit');
resetFixture();$client->effective=true;check($run(true)['success']&&$client->bans===0,'Effective ticket not renewed');
resetFixture();$client->effective=false;$client->banOk=false;check($run(true)['code']==='firewall_unconfirmed','Unconfirmed ban explicit');
echo "PASS: {$checks} promotion checks; memory-only, no host changes\n";
