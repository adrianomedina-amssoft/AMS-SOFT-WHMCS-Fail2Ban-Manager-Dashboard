<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {
    public static array $cfg=['schema_version'=>'21','ai_auto_create_filter'=>'0'], $decisions=[];
    public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}
    public static function decision($id,$code,...$a){self::$decisions[$id]=$code;}
    public static function logEvent(...$a){}
}
class AIAnalyzer {}
class JailConfig {public function __construct(...$a){} public function readJailLocal(){return [];}}
class Fail2BanClient {
    public int $bans=0;
    public function hasEffectiveBan(...$a){return false;}
    public function banIP(...$a){$this->bans++;return true;}
}
class Privileged {
    public static int $reads=0;public static array $ports=[80,443];public static string $protocol='tcp';
    public static function run($args){
        if($args[0]==='--read-budget'&&$args[2]==='ban-coverage'){self::$reads++;return ['success'=>true,'observed_at'=>time(),'entries'=>[['ip'=>'203.0.113.7','effective'=>true,'protocol'=>self::$protocol,'ports'=>self::$ports,'expires_at'=>time()+3600,'jail'=>'native-other','ticket'=>'unchanged']]];}
        if($args[0]==='ensure-ai-jail')return ['success'=>true];
        throw new \RuntimeException('Unexpected operation');
    }
}
require dirname(__DIR__).'/lib/CycleBudget.php';require dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__).'/lib/Safety.php';require dirname(__DIR__).'/lib/Policy.php';require dirname(__DIR__).'/lib/BlockedTasks.php';require dirname(__DIR__).'/lib/AutoBanEngine.php';
$checks=0;function check($v,$m){global $checks;if(!$v)throw new \RuntimeException($m);$checks++;}
$client=new Fail2BanClient;$engine=new AutoBanEngine(null,$client);
$s=['ip'=>'203.0.113.7','classification'=>'ban','confidence'=>99,'_suggestion_id'=>7,'evidence'=>['203.0.113.7 - - ['.date('d/M/Y:H:i:s O').'] "GET /.env HTTP/1.1" 404 10 "-" "fixture"']];
check($engine->executeBan($s,42),'Existing HTTP protection not accepted');
check($client->bans===0,'Manual approval renewed or duplicated native ban');
check(Database::$decisions[7]==='protected_existing','Existing protection misreported as execution');
check($engine->executeBan($s,42)&&Privileged::$reads===1&&$client->bans===0,'Bulk/request reused an unbounded number of snapshots');
Privileged::$ports=[22];$client=new Fail2BanClient;$engine=new AutoBanEngine(null,$client);
check($engine->executeBan($s,42)&&$client->bans===1,'SSH-only protection falsely accepted for HTTP');
Privileged::$ports=[80,443];Privileged::$protocol='udp';$client=new Fail2BanClient;$engine=new AutoBanEngine(null,$client);
check($engine->executeBan($s,42)&&$client->bans===1,'UDP protection falsely accepted for HTTP TCP');
Database::$cfg['ai_whitelist_ips']='203.0.113.7';$client=new Fail2BanClient;$engine=new AutoBanEngine(null,$client);
check(!$engine->executeBan($s,42)&&$client->bans===0,'Whitelist bypassed by manual approval');
echo "PASS: {$checks} manual protection checks; memory-only, no host/SQL/provider\n";
