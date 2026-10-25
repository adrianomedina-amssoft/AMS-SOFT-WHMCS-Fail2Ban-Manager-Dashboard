<?php
if(PHP_SAPI!=='cli')exit(1);
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__,4).'/configuration.php';
require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{AIAnalyzer,AutoBanEngine,Database,Fail2BanClient,BehaviorStore};
use WHMCS\Database\Capsule;
$capsule=new Capsule();$capsule->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,
    'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4','collation'=>'utf8mb4_unicode_ci','prefix'=>'']);
$capsule->setAsGlobal();$capsule->bootEloquent();
class FixtureAI extends AIAnalyzer {
    public array $result=[],$lastBatch=[];public bool $fail=false;public int $calls=0;
    public function analyzeSubjects(array $lines,array $context): array {
        $this->requestStarting();
        $this->lastBatch=array_keys($context);
        $this->calls++;if($this->fail)throw new RuntimeException('Fixture API unavailable');return $this->result;
    }
}
class FixtureEngine extends AutoBanEngine {
    public array $banned=[];
    public function executeBan(array $s,?int $admin=null): bool {
        if(empty($s['_evidence_validated'])||$s['confidence']<90)throw new RuntimeException('Unsafe authority reached executor');
        if(!parent::validateEvidenceFilter($s))return false;
        $this->banned[]=$s['ip'];return true;
    }
}
$checks=0;function check($value,$label){global $checks;if(!$value)throw new RuntimeException($label);$checks++;}
$db=Capsule::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)
    throw new RuntimeException('Production cycle still active; rerun after it completes');
$db->beginTransaction();
Database::setConfig('schema_version','23'); // Legacy engine regression; schema24 admission is covered separately.
Database::setConfig('ai_rule_requests','{}');Database::setConfig('ai_history_validation_per_cycle','0');
try {
    // Mask production backlog inside this rolled-back transaction only.
    Capsule::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>Capsule::raw('revision')]);
    foreach(['ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold','ai_auto_create_filter'=>'0',
        'ai_behavior_enabled'=>'1','ai_behavior_require_repetition'=>'0','ai_cycle_max_calls'=>'1',
        'ai_threshold_high'=>'2:60','ai_auto_min_confidence'=>'90','ai_behavior_min_events'=>'2'] as $k=>$v)Database::setConfig($k,$v);
    $ai=new FixtureAI('openai','fixture');$engine=new FixtureEngine($ai,new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client'));
    $ids=[];$ips=['198.51.100.241','198.51.100.242','198.51.100.243'];
    foreach($ips as $i=>$ip) {
        $line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET /.env HTTP/1.1" 404 100 "-" "scanner"';
        $id=hash('sha256','fixture'.bin2hex(random_bytes(8)));$ids[]=$id;$pattern=BehaviorStore::pattern($line);
        $event=['id'=>hash('sha256',$id),'ip'=>$ip,'line'=>$line,'time'=>time(),'pattern'=>$pattern];
        Capsule::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$id,'ip'=>$ip,'source_log'=>'/var/log/amsfb-test',
            'pattern'=>$pattern,'bucket'=>date('Y-m-d H:i:s',time()-$i*600),'events'=>1,'revision'=>1,'samples'=>json_encode([$event])]);
        if($i<2)$ai->result[]=['ip'=>$ip,'severity'=>'high','confidence'=>95,'action'=>'ban','threat'=>'Probe','evidence'=>[$line],
            'filter_name'=>'fixture-env','failregex'=>'^<HOST> - .*"GET /\\.env HTTP/1\\.1" 404'];
    }
    $engine->runAnalysis();
    check(count($engine->banned)===1,'Only the second validated peer reaches campaign authority; unclassified third is excluded');
    check(!in_array($ips[2],$engine->banned,true),'Missing peer classification never implies ban');
    check(Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$ids[2])->value('retry_at')!==null,'Missing item stays pending with backoff');
    $d=Capsule::table('mod_amssoft_fail2ban_detections')->whereIn('ip',$ips)->count();
    // Force/manual reuses events but must not acknowledge or auto-execute.
    Capsule::table('mod_amssoft_fail2ban_rollups')->whereIn('id',$ids)->update(['analyzed_revision'=>0,'retry_at'=>null]);
    $engine->runAnalysis(true);
    check(count($engine->banned)===1,'Manual request never executes automatic bans');
    check(Capsule::table('mod_amssoft_fail2ban_detections')->whereIn('ip',$ips)->count()===$d,'Force does not multiply source identities');
    check((int)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$ids[0])->value('analyzed_revision')===0,'Manual review leaves automatic work pending');
    $beforeFailure=Capsule::table('mod_amssoft_fail2ban_rollups')->whereIn('id',$ids)->get()->keyBy('ip');
    $ai->fail=true;$engine->runAnalysis();$selected=$ai->lastBatch;$preserved=(bool)$selected;
    foreach(Capsule::table('mod_amssoft_fail2ban_rollups')->whereIn('id',$ids)->get() as $row){
        if(in_array($row->ip,$selected,true))$preserved=$preserved&&$row->retry_at!==null&&$row->processing_state==='retry';
        else foreach(['analyzed_revision','attempts','retry_at','processing_state'] as $field)$preserved=$preserved&&$row->$field===$beforeFailure[$row->ip]->$field;
    }
    check($preserved,'API failure defers exactly selected peers and preserves unselected tasks regardless of urgency order');
    $ai->fail=false;foreach($ai->result as &$s)$s['confidence']=89;unset($s);
    Capsule::table('mod_amssoft_fail2ban_rollups')->whereIn('id',$ids)->update(['retry_at'=>null]);
    $engine->runAnalysis();check(count($engine->banned)===1,'Below configured automatic confidence stays review-only');
} finally {$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} adaptive engine checks; real validator, fake API/executor, SQL rolled back\n";
