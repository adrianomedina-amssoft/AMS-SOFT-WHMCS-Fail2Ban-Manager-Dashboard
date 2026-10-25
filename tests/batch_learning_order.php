<?php
namespace AMS\Fail2Ban {
    class Fail2BanClient {
        public array $bans=[];
        public function hasEffectiveBan(...$a){return false;}
        public function banIP($j,$ip){$this->bans[]=$ip;return true;}
    }
    class Privileged {
        public static function run($a){
            if($a[0]==='ban-coverage')return ['success'=>true,'observed_at'=>time(),'entries'=>[]];
            if($a[0]==='ensure-ai-jail')return ['success'=>true];
            if($a[0]==='normalize-filter'){$p=json_decode(file_get_contents($a[1]),true);return ['success'=>true,'patterns'=>$p['patterns'],'matched_sha256'=>array_map(fn($l)=>hash('sha256',$l),$p['evidence'])];}
            throw new \RuntimeException('Unexpected native validation or mutation: '.$a[0]);
        }
    }
    class ManagedRules {
        public static array $tasks=[],$queued=[];public static bool $sawCompleted=false;
        public static function enqueueAutomatic($s){self::$queued[]=$s['_suggestion_id'];return ['success'=>false,'code'=>'promotion_queued'];}
        public static function processRequest($c){
            $n=\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->whereIn('id',self::$tasks)->whereColumn('analyzed_revision','>=','revision')->count();
            self::$sawCompleted=$n===10&&count(self::$queued)===10;
            if(!self::$sawCompleted)throw new \RuntimeException('Learning ran before all paid decisions were completed');
            throw new CycleBudgetExceeded('Fixture learning deadline; completed decisions must survive');
        }
    }
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{Database,AIAnalyzer,AutoBanEngine,Fail2BanClient,ManagedRules};use WHMCS\Database\Capsule as C;
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
class BatchFixtureAI extends AIAnalyzer {
    public int $calls=0;
    public function analyzeSubjects(array $lines,array $context): array {
        $this->requestStarting();$this->calls++;$out=[];
        foreach($context as $ip=>$value){$e=array_values(array_filter($lines,fn($l)=>str_starts_with($l,$ip.' ')));$out[]=['ip'=>$ip,'action'=>'ban','severity'=>'critical','confidence'=>99,'threat'=>'fixture','evidence'=>$e,'filter_name'=>'fixture','failregex'=>'^<HOST> .*env'];}
        return $out;
    }
}
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');
$db->beginTransaction();
Database::setConfig('schema_version','23'); // Paid-batch ordering contract before mandatory admission.
try{
    C::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>C::raw('revision')]);
    foreach(['ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold','ai_auto_create_filter'=>'1','ai_cycle_max_calls'=>'1','ai_cycle_seconds'=>'180','ai_history_validation_per_cycle'=>'0','ai_review_auto_recovery_enabled'=>'0','ai_rule_requests'=>'{}','ai_whitelist_ips'=>'','ai_threshold_critical'=>'1:30'] as $k=>$v)Database::setConfig($k,$v);
    $source='/var/log/batch-fixture-'.bin2hex(random_bytes(8));
    for($i=1;$i<=10;$i++){
        $ip='198.18.31.'.$i;$id=hash('sha256',$source.$i);ManagedRules::$tasks[]=$id;$p=hash('sha256','pattern'.$i);
        $line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET /.env HTTP/1.1" 404 10 "-" "fixture"';
        $event=['id'=>hash('sha256',$id.'event'),'ip'=>$ip,'line'=>$line,'time'=>time(),'pattern'=>$p];
        C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$id,'ip'=>$ip,'source_log'=>$source,'pattern'=>$p,'family_key'=>'env-exposure','bucket'=>date('Y-m-d H:i:s'),'events'=>1,'revision'=>1,'samples'=>json_encode([$event])]);
    }
    $ai=new BatchFixtureAI('openai','fixture');$client=new Fail2BanClient;$engine=new AutoBanEngine($ai,$client);$engine->runAnalysis();
    if(!ManagedRules::$sawCompleted||count($client->bans)!==10||$ai->calls!==1)throw new RuntimeException('Paid batch not preserved across learning deadline');
    $metrics=\AMS\Fail2Ban\QueueTelemetry::summary()['last'];
    if($metrics['completed']!==10||$metrics['error']!=='')throw new RuntimeException('Learning timeout damaged cycle completion');
    $engine->runAnalysis();if($ai->calls!==1)throw new RuntimeException('Completed batch sent to API again');
}finally{$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: 3 ten-decision batch/learning deadline checks; SQL rolled back, fake API/ban/native\n";
}
