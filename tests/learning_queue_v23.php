<?php
// Pure fixtures: SQL, native operations and temporary files live in memory.
namespace WHMCS\Database {
    class Capsule {
        public static array $rules=[];
        public static int $updates=5;
        public static function table($name){return new Query();}
    }
    class Query {
        private array $where=[];
        public function where(...$args){if(is_callable($args[0]))$args[0]($this);else $this->where[$args[0]]=$args[1]??null;return $this;}
        public function orWhere(...$args){return $this;}
        public function orderByDesc(...$args){return $this;}
        public function limit(...$args){return $this;}
        public function first(){return isset(Capsule::$rules[$this->where['scope_key']??''])?(object)Capsule::$rules[$this->where['scope_key']]:null;}
        public function get(){return [];}
        public function max($key){return null;}
        public function count(){return ($this->where['action']??'')==='native_rule_extended'?Capsule::$updates:0;}
        public function updateOrInsert($key,$data){Capsule::$rules[$key['scope_key']]=$key+$data;}
    }
}
namespace AMS\Fail2Ban {
    if(PHP_SAPI!=='cli')exit(1);
    class MemoryFiles {public static array $files=[];public static int $sequence=0;}
    function tempnam($dir,$prefix){$name='memory:'.$prefix.(++MemoryFiles::$sequence);MemoryFiles::$files[$name]='';return $name;}
    function file_put_contents($name,$contents){MemoryFiles::$files[$name]=$contents;return strlen($contents);}
    function unlink($name){unset(MemoryFiles::$files[$name]);return true;}
    function hash_file($algorithm,$name){return hash($algorithm,'fixture');}
    function posix_geteuid(){return 0;}
    function function_exists($name){return $name==='posix_geteuid'||\function_exists($name);}
    class Database {
        public static array $cfg=[],$suggestions=[],$decisions=[],$created=[],$events=[],$order=[];
        public static function getConfig($key,$default=''){return self::$cfg[$key]??$default;}
        public static function setConfig($key,$value){self::$cfg[$key]=$value;}
        public static function getSuggestion($id){return self::$suggestions[$id]??null;}
        public static function decision($id,$code,$result){self::$decisions[$id]=[$code,$result];self::$order[]=$id;}
        public static function updateFilterCreated($id){self::$created[]=$id;}
        public static function familyStats(...$args){return ['occurrences'=>100,'distinct_ips'=>100];}
        public static function incrementConfig($key){}
        public static function logEvent(...$args){self::$events[]=$args;}
    }
    class AutoBanEngine {
        public static int $normalizations=0,$validations=0;
        public static bool $needsNormalization=false,$invalid=false,$deadline=false,$unavailable=false;
        public static function normalizeEvidenceFilter(&$s){
            self::$normalizations++;
            if(self::$deadline)throw new CycleBudgetExceeded('fixture');
            if(self::$unavailable)throw new \RuntimeException('fixture');
            if(self::$needsNormalization)$s['failregex']='^<HOST> normalized$';
        }
        public static function validateEvidenceFilter($s){
            self::$validations++;
            return !self::$invalid&&(!self::$needsNormalization||$s['failregex']==='^<HOST> normalized$');
        }
    }
    class Fail2BanClient {
        public function getJails(){return array_keys(Privileged::$jails);}
        public function banIP(...$args){throw new \RuntimeException('Learning must never ban');}
    }
    class JailConfig {public function __construct(...$args){}}
    class Privileged {
        public static array $jails=[],$states=[],$calls=[];
        public static bool $covered=false;
        public static function run($args){
            self::$calls[]=$args[0];
            if($args[0]==='effective-config')return ['success'=>true,'jails'=>self::$jails];
            if($args[0]==='jail-filter-state')return self::$states[$args[1]]??['success'=>true,'prefregex'=>null,'ignoreregex'=>[],'patterns'=>['^<HOST> attack$'],'paths'=>[__FILE__]];
            if($args[0]==='filter-coverage')return ['success'=>true,'covered'=>self::$covered?count(json_decode(MemoryFiles::$files[$args[2]],true)):0];
            if($args[0]==='extend-managed-rule'){
                \WHMCS\Database\Capsule::$updates++;
                return ['success'=>true];
            }
            throw new \RuntimeException('Unexpected operation: '.$args[0]);
        }
    }
    class FilterManager {
        public static int $created=0;
        public static array $diagnostic=['success'=>true];
        public function __construct(...$args){}
        public static function getAllowedLogs(){return [__FILE__,dirname(__DIR__).'/lib/ManagedRules.php'];}
        public function loadedFilterDiagnostic(...$args){return self::$diagnostic;}
        public function filterExists($name){return false;}
        public function jailExists($name){return false;}
        public function createFilter(...$args){self::$created++;return true;}
        public function createJailForFilter($jail,$filter,$params){Privileged::$jails[$jail]=['filter'=>'amsfb-'.$filter,'logpath'=>$params['logpath'],'enabled'=>'true'];return true;}
        public function reloadJail($jail){return true;}
    }
    require dirname(__DIR__).'/lib/Safety.php';
    require dirname(__DIR__).'/lib/AttackFamily.php';
    require dirname(__DIR__).'/lib/Policy.php';
    require dirname(__DIR__).'/lib/CycleBudget.php';
    require dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
    require dirname(__DIR__).'/lib/ManagedRules.php';

    $checks=0;
    function check($value,$message){global $checks;if(!$value)throw new \RuntimeException($message);$checks++;}
    function resetFixture(){
        Database::$cfg=['ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold','ai_learning_jobs_per_cycle'=>'10'];
        Database::$suggestions=Database::$decisions=Database::$created=Database::$events=Database::$order=[];
        \WHMCS\Database\Capsule::$rules=[];\WHMCS\Database\Capsule::$updates=5;
        Privileged::$jails=['amsfb-wordpress-access'=>['filter'=>'amsfb-wordpress-access','logpath'=>__FILE__,'enabled'=>'true']];
        Privileged::$states=Privileged::$calls=[];Privileged::$covered=false;
        FilterManager::$created=0;FilterManager::$diagnostic=['success'=>true];
        AutoBanEngine::$normalizations=AutoBanEngine::$validations=0;
        AutoBanEngine::$needsNormalization=AutoBanEngine::$invalid=AutoBanEngine::$deadline=AutoBanEngine::$unavailable=false;
        CycleBudget::end();
    }
    function job($id,$changes=[]){return array_replace(['id'=>$id,'classification'=>'ban','status'=>'pending','decision_code'=>'promotion_queued',
        'ip'=>'203.0.113.7','confidence'=>99,'source_log'=>__FILE__,'filter_name'=>'provider-wordpress','failregex'=>'^<HOST> attack$',
        'evidence'=>['203.0.113.7 - - [14/Oct/2026:12:00:00 -0300] "GET /wp-admin/ HTTP/1.1" 403 10 "-" "fixture"']],$changes);}
    function queueJobs($jobs,$requests=[]){
        $queue=[];
        foreach($jobs as $s){$id=$s['id'];Database::$suggestions[$id]=$s;$queue[$id]=$requests[$id]??['origin'=>'automatic','admin'=>null,'last_code'=>'update_daily_limit','retry_at'=>0];}
        Database::$cfg['ai_rule_requests']=json_encode($queue);
    }
    function runQueue(){return ManagedRules::processRequest(new Fail2BanClient());}
    function queue(){return json_decode(Database::$cfg['ai_rule_requests'],true);}

    resetFixture();queueJobs([job(1)]);$m=runQueue();
    check(AutoBanEngine::$normalizations===0&&AutoBanEngine::$validations===1,'Exhausted known update normalized or skipped validation');
    check($m===['attempted'=>1,'completed'=>0,'deferred'=>1,'review'=>0]&&queue()[1]['last_code']==='update_daily_limit','Known quota request lost pending state');
    check(queue()[1]['retry_at']>time(),'Quota retry was not scheduled');
    check(Database::$decisions[1][1]['banned']===false,'Learning result claims a ban');
    check(runQueue()['attempted']===0,'Future retry ran early');

    resetFixture();\WHMCS\Database\Capsule::$updates=0;queueJobs([job(1)]);runQueue();
    check(AutoBanEngine::$normalizations===1&&Database::$decisions[1][1]['code']==='extended','Reset quota did not restore normal extension');
    foreach([null,'daily_limit','existing_rule_review','filter_branch'] as $previous){
        resetFixture();queueJobs([job(1)],[1=>['origin'=>'automatic','last_code'=>$previous]]);runQueue();
        check(AutoBanEngine::$normalizations===1,'Unrelated refusal skipped normalization');
    }

    resetFixture();Privileged::$covered=true;queueJobs([job(1)]);runQueue();
    check(Database::$decisions[1][1]['code']==='reused'&&queue()===[]&&AutoBanEngine::$normalizations===0,'Update quota prevented reuse');
    resetFixture();Privileged::$jails=[];queueJobs([job(1)]);runQueue();
    check(Database::$decisions[1][1]['code']==='created'&&FilterManager::$created===1,'Update quota prevented creation');
    foreach([false,true] as $create){
        resetFixture();AutoBanEngine::$needsNormalization=true;
        if($create)Privileged::$jails=[];else Privileged::$covered=true;
        queueJobs([job(1)]);runQueue();
        check(AutoBanEngine::$normalizations===1&&Database::$decisions[1][1]['success'],'Raw validation failure prevented normalized reuse/creation');
    }

    resetFixture();queueJobs([job(1,['decision_code'=>'blocked','status'=>'auto_executed']),job(2)]);$m=runQueue();
    check(AutoBanEngine::$validations===1&&$m['deferred']===2,'Exact requests repeated promotion work');
    check(Database::$decisions[1][0]==='blocked'&&Database::$decisions[2][0]==='update_daily_limit','Shared work overwrote per-decision result');
    check(Database::$suggestions[1]['status']==='auto_executed'&&Database::$suggestions[2]['status']==='pending','Shared work changed ban status');
    check(isset(queue()[1],queue()[2]),'Dedup discarded a durable request');
    resetFixture();Privileged::$covered=true;queueJobs([job(1),job(2)]);$m=runQueue();
    check($m['completed']===2&&Database::$created===[1,2]&&queue()===[],'Dedup did not complete each decision');
    resetFixture();queueJobs([job(1),job(2)],[1=>['origin'=>'automatic'],2=>['origin'=>'automatic']]);runQueue();
    check(AutoBanEngine::$normalizations===1&&AutoBanEngine::$validations===1,'Exact new requests repeated normalization');
    resetFixture();Database::$cfg['ai_learning_jobs_per_cycle']='1';
    queueJobs([job(1),job(2,['failregex'=>'^<HOST> other$']),job(3)]);$m=runQueue();
    check(AutoBanEngine::$validations===1&&$m['deferred']===2&&Database::$order===[1,3],'Job cap prevented exact duplicate checkpoint');
    check(!isset(queue()[2]['retry_at'])||queue()[2]['retry_at']===0,'Unprocessed distinct request changed backoff');
    check(!isset(Database::$decisions[2]),'Job cap executed a distinct proof');

    foreach(['source_log'=>dirname(__DIR__).'/lib/ManagedRules.php','failregex'=>'^<HOST> different$',
        'evidence'=>['203.0.113.7 - - [14/Oct/2026:12:00:01 -0300] "GET /wp-admin/ HTTP/1.1" 403 10 "-" "other"'],
        'confidence'=>98,'ip'=>'203.0.113.8','filter_name'=>'other-provider'] as $field=>$value){
        resetFixture();queueJobs([job(1),job(2,[$field=>$value])]);runQueue();
        check(AutoBanEngine::$validations===2,'Different '.$field.' shared authority');
    }
    resetFixture();$first=job(1);$second=job(2);$second['evidence']=json_encode($second['evidence']);queueJobs([$first,$second]);runQueue();
    check(AutoBanEngine::$validations===2,'Non-identical evidence representations were coalesced');

    resetFixture();queueJobs([job(1),job(2)],[1=>['origin'=>'automatic'],2=>['origin'=>'manual','admin'=>42]]);runQueue();
    check(Database::$order===[2,1]&&AutoBanEngine::$normalizations===2,'Manual priority or policy separation lost');
    resetFixture();queueJobs([job(1),job(2)],[1=>['origin'=>'manual','admin'=>41],2=>['origin'=>'manual','admin'=>42]]);runQueue();
    check(AutoBanEngine::$normalizations===2,'Different audit admins shared execution');
    resetFixture();Database::$cfg['ai_confirmed_auto']='0';queueJobs([job(1),job(2)],[1=>['origin'=>'automatic'],2=>['origin'=>'manual','admin'=>42]]);runQueue();
    check(Database::$order===[2]&&isset(queue()[1]),'Manual result bypassed automatic admission');
    resetFixture();queueJobs([job(1),job(2,['status'=>'rejected'])]);runQueue();
    check(!isset(queue()[2],Database::$decisions[2]),'Rejected duplicate was executed');
    resetFixture();queueJobs([job(1,['confidence'=>0]),job(2)]);runQueue();
    check(Database::$decisions[1][1]['code']==='policy_refused'&&Database::$decisions[2][1]['code']==='update_daily_limit','Confidence gate shared a refusal across decisions');

    resetFixture();Privileged::$states['amsfb-wordpress-access']=['success'=>false];queueJobs([job(1)]);runQueue();
    check(Database::$decisions[1][1]['code']==='existing_rule_review'&&FilterManager::$created===0,'Missing loaded candidate created a duplicate family');
    resetFixture();FilterManager::$diagnostic=['success'=>false,'code'=>'filter_branch','error'=>'Each regex needs source evidence'];queueJobs([job(1)]);runQueue();
    check(Database::$decisions[1][1]['code']==='filter_branch'&&Database::$decisions[1][1]['learning_state']==='review','Unproved branch weakened or hidden by quota');
    check(Database::$decisions[1][1]['candidate_diagnostics'][0]['code']==='filter_branch','Branch diagnostic lost');
    resetFixture();AutoBanEngine::$invalid=true;queueJobs([job(1)]);runQueue();
    check(Database::$decisions[1][1]['code']==='filter_positive'&&Privileged::$calls===[],'Invalid candidate bypassed full validation');

    resetFixture();queueJobs([job(1)]);CycleBudget::begin(0);$m=runQueue();CycleBudget::end();
    check($m['attempted']===0&&isset(queue()[1]),'Cycle budget dropped request');
    resetFixture();AutoBanEngine::$deadline=true;queueJobs([job(1)],[1=>['origin'=>'automatic']]);$m=runQueue();
    check($m['deferred']===1&&isset(queue()[1])&&Database::$decisions===[],'Normalization deadline lost request');
    resetFixture();AutoBanEngine::$unavailable=true;queueJobs([job(1),job(2)],[1=>['origin'=>'automatic'],2=>['origin'=>'automatic']]);runQueue();
    check(AutoBanEngine::$normalizations===2&&count(queue())===2,'Transient exception was coalesced or dropped requests');
    resetFixture();queueJobs([job(1)]);runQueue();$q=queue();$q[1]['retry_at']=0;Database::$cfg['ai_rule_requests']=json_encode($q);Privileged::$covered=true;runQueue();
    check(Database::$decisions[1][1]['code']==='reused','Prior processing pass cached quota over newly available reuse');
    check(MemoryFiles::$files===[],'Memory temporary files leaked');
    check(!in_array('banip',Privileged::$calls,true),'Learning requested a ban');
    echo "PASS: {$checks} pure learning queue checks; no host writes, native calls, SQL or API\n";
}
