<?php
namespace WHMCS\Database {
    class Capsule {
        public static array $rules=[];
        public static int $dailyUpdates=0;
        public static function table($name){return new Query($name);}
    }
    class Query {
        private array $where=[];
        public function __construct(private string $name){}
        public function where(...$a){if(is_callable($a[0])){$a[0]($this);return $this;}$this->where[$a[0]]=$a[1]??null;return $this;}
        public function orWhere(...$a){return $this;}
        public function orderByDesc(...$a){return $this;}
        public function limit(...$a){return $this;}
        public function first(){return isset(Capsule::$rules[$this->where['scope_key']??''])?(object)Capsule::$rules[$this->where['scope_key']]:null;}
        public function get(){return [];}
        public function count(){return ($this->where['action']??'')==='native_rule_extended'?Capsule::$dailyUpdates:0;}
        public function max($key){return null;}
        public function updateOrInsert($key,$data){Capsule::$rules[$key['scope_key']]=$key+$data;}
    }
}
namespace AMS\Fail2Ban {
    class Database {
        public static array $cfg=['schema_version'=>'21','ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold'];
        public static array $stats=['occurrences'=>100,'distinct_ips'=>100];
        public static array $suggestions=[],$decisions=[];
        public static function getSuggestion($id){return self::$suggestions[$id]??null;}
        public static function decision($id,$code,$r=null){self::$decisions[$id]=[$code,$r];}
        public static function updateFilterCreated($id){}
        public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}
        public static function setConfig($k,$v){self::$cfg[$k]=$v;}
        public static function familyStats(...$a){return self::$stats;}
        public static function incrementConfig($k){return self::$cfg[$k]=(int)(self::$cfg[$k]??0)+1;}
        public static function logEvent(...$a){}
    }
    class AutoBanEngine {public static function validateEvidenceFilter($s){return true;}public static function normalizeEvidenceFilter(&$s){}}
    class Fail2BanClient {public function getJails(){return array_keys(Privileged::$jails);}}
    class JailConfig {public function __construct(...$a){}}
    class Privileged {
        public static array $jails=[];
        public static array $uncovered=[];
        public static function run($args){
            if($args[0]==='effective-config')return ['success'=>true,'jails'=>self::$jails];
            if($args[0]==='jail-filter-state')return ['success'=>true,'prefregex'=>null,'ignoreregex'=>[],'patterns'=>['^<HOST> attack$'],'paths'=>[__FILE__]];
            if($args[0]==='filter-coverage'){
                $lines=json_decode(file_get_contents($args[2]),true);$family=AttackFamily::fromLine($lines[0]);
                return ['success'=>true,'covered'=>!in_array($args[1],self::$uncovered,true)&&ManagedRules::nameFamily(Safety::filterName(self::$jails[$args[1]]['filter']))===$family?count($lines):0];
            }
            throw new \RuntimeException('Unexpected helper operation: '.$args[0]);
        }
    }
    class FilterManager {
        public static int $created=0;public static array $bad=[];
        public function __construct(...$a){}
        public static function getAllowedLogs(){return [__FILE__];}
        public function loadedFilterDiagnostic($j,...$a){return ['success'=>!in_array($j,self::$bad),'code'=>'injected'];}
        public function filterExists($name){return isset(Privileged::$jails['amsfb-'.$name]);}
        public function jailExists($name){return isset(Privileged::$jails[$name]);}
        public function createFilter(...$a){self::$created++;return true;}
        public function createJailForFilter($j,$f,$params){Privileged::$jails[$j]=['filter'=>'amsfb-'.$f,'logpath'=>__FILE__,'enabled'=>'true'];return true;}
        public function reloadJail($j){return true;}
    }
    require dirname(__DIR__).'/lib/Safety.php';require dirname(__DIR__).'/lib/AttackFamily.php';require dirname(__DIR__).'/lib/Policy.php';require dirname(__DIR__).'/lib/ManagedRules.php';require dirname(__DIR__).'/lib/CycleBudget.php';require dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
    $checks=0;function check($v,$m){global $checks;if(!$v)throw new \RuntimeException($m);$checks++;}
    $client=new Fail2BanClient();
    function suggestion($n){$ip='203.0.113.'.$n;return ['ip'=>$ip,'action'=>'ban','confidence'=>99,'source_log'=>__FILE__,'failregex'=>'^<HOST> attack$','filter_name'=>'provider-name-'.$n,'_pattern'=>hash('sha256',(string)$n),'evidence'=>[$ip.' - - [13/Oct/2026:12:00:00 -0300] "GET /site'.$n.'/wp-admin/ HTTP/1.1" 403 10 "-" "agent"']];}
    foreach(range(1,100) as $n){$r=ManagedRules::promote(suggestion($n),$client);check($r['success'],'Same-family promotion failed');check($r['code']===($n===1?'created':'reused'),'Rule was not reused');}
    check(FilterManager::$created===1&&count(Privileged::$jails)===1,'100 peers created more than one jail');
    \WHMCS\Database\Capsule::$rules=[];Privileged::$jails=['amsfb-wordpress-bad'=>['filter'=>'amsfb-wordpress-bad'],'amsfb-wordpress-good'=>['filter'=>'amsfb-wordpress-good']];
    FilterManager::$bad=['amsfb-wordpress-bad'];$s=suggestion(101);$r=ManagedRules::promote($s,$client);
    check($r['success']&&$r['jail']==='amsfb-wordpress-good','First incompatible candidate prevented valid reuse');
    Database::$cfg['native_detection_quarantine']=json_encode(array_keys(Privileged::$jails));\WHMCS\Database\Capsule::$rules=[];
    $r=ManagedRules::promote(suggestion(102),$client);check(!$r['success']&&FilterManager::$created===1,'Quarantine caused duplicate jail or reactivation');
    Database::$stats=['occurrences'=>1,'distinct_ips'=>1];$r=ManagedRules::promote(suggestion(103),$client);
    check(!$r['success']&&$r['code']==='promotion_threshold','Learning bypassed diverse-peer gate');
    Database::$stats=['occurrences'=>100,'distinct_ips'=>100];Database::$cfg['native_detection_quarantine']='[]';\WHMCS\Database\Capsule::$rules=[];Privileged::$jails=[];
    for($n=0;$n<22;$n++)Privileged::$jails['amsfb-env-old-'.$n]=['filter'=>'amsfb-env-old-'.$n,'logpath'=>__FILE__,'enabled'=>'true'];
    for($n=0;$n<44;$n++)Privileged::$jails['amsfb-disabled-'.$n]=['filter'=>'amsfb-env-disabled-'.$n,'logpath'=>__FILE__,'enabled'=>'false'];
    $r=ManagedRules::promote(suggestion(104),$client);check($r['success']&&$r['code']==='created','Disabled legacy prevented new family below active cap');
    check(ManagedRules::inventory(Privileged::$jails)===['enabled'=>23,'disabled'=>44],'New jail inventory is incorrect');
    \WHMCS\Database\Capsule::$rules=[];Privileged::$jails=[];
    for($n=0;$n<32;$n++)Privileged::$jails['amsfb-env-full-'.$n]=['filter'=>'amsfb-env-full-'.$n,'logpath'=>__FILE__,'enabled'=>'true'];
    $r=ManagedRules::promote(suggestion(105),$client);check(!$r['success']&&$r['code']==='managed_jail_limit','Active cap did not refuse creation');
    \WHMCS\Database\Capsule::$rules=[];Privileged::$jails=['amsfb-wordpress-a'=>['filter'=>'amsfb-wordpress-a','enabled'=>'true','logpath'=>__FILE__],'amsfb-wordpress-z'=>['filter'=>'amsfb-wordpress-z','enabled'=>'true','logpath'=>__FILE__]];
    Privileged::$uncovered=array_keys(Privileged::$jails);FilterManager::$bad=['amsfb-wordpress-z'];\WHMCS\Database\Capsule::$dailyUpdates=5;
    $r=ManagedRules::promote(suggestion(106),$client);
    check($r['code']==='update_daily_limit'&&$r['primary_code']==='update_daily_limit','Invalid later candidate hid valid quota refusal');
    check(count($r['candidate_diagnostics'])===2&&$r['candidate_diagnostics'][1]['code']==='injected','Per-candidate explanation missing');
    $job=suggestion(107)+['id'=>107,'classification'=>'ban','status'=>'auto_executed','decision_code'=>'blocked'];
    Database::$suggestions[107]=$job;ManagedRules::enqueueAutomatic($job);ManagedRules::enqueueAutomatic($job);
    check(count(json_decode(Database::$cfg['ai_rule_requests'],true))===1,'Automatic job duplicated');
    CycleBudget::begin(0);$m=ManagedRules::processRequest($client);check($m['attempted']===0&&isset(json_decode(Database::$cfg['ai_rule_requests'],true)[107]),'Budget lost durable job');CycleBudget::end();
    $m=ManagedRules::processRequest($client);$queue=json_decode(Database::$cfg['ai_rule_requests'],true);
    check($m['deferred']===1&&$queue[107]['retry_at']>time(),'Daily limit deleted job');
    check(Database::$decisions[107][0]==='blocked','Learning overwrote confirmed ban');
    $m=ManagedRules::processRequest($client);check($m['attempted']===0,'Cooldown/retry_at ignored');
    $queue[107]['retry_at']=0;Database::$cfg['ai_rule_requests']=json_encode($queue);Database::$cfg['ai_auto_enabled']='0';
    check(ManagedRules::processRequest($client)['attempted']===0,'Disabled automatic policy executed queued job');
    Database::$cfg['ai_auto_enabled']='1';Database::$suggestions[107]['status']='rejected';ManagedRules::processRequest($client);
    check(json_decode(Database::$cfg['ai_rule_requests'],true)===[],'Rejected decision stayed queued');
    echo "PASS: {$checks} managed learning checks; memory-only SQL/helper/filter collaborators\n";
}
