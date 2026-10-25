<?php
namespace AMS\Fail2Ban {
    class Fail2BanClient {}
    class Privileged {
        public static array $calls=[];
        public static function run(array $args): array {
            self::$calls[]=$args[0];
            if($args[0]==='normalize-filter'){
                $p=json_decode(file_get_contents($args[1]),true);
                if(str_contains(implode("\n",$p['patterns']),'NEVER'))return ['success'=>false,'code'=>'filter_positive'];
                $hashes=[];foreach($p['evidence'] as $line)if(str_contains($line,'wp-admin'))$hashes[]=hash('sha256',$line);
                return ['success'=>true,'patterns'=>$p['patterns'],'matched_sha256'=>$hashes];
            }
            if($args[0]==='ban-coverage'){
                return ['success'=>true,'observed_at'=>time(),'entries'=>$args[1]==='198.18.20.1'?[['ip'=>$args[1],'effective'=>true,'protocol'=>'tcp','ports'=>[80,443],'expires_at'=>time()+3600,'jail'=>'existing-native','ticket'=>'fixture-ticket']]:[]];
            }
            throw new \RuntimeException('Unexpected privileged operation: '.$args[0]);
        }
    }
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,HistoricalDecisions,AutoBanEngine,Fail2BanClient,CycleBudget,BehaviorStore,Privileged};
$c=new C();$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
class CachedFixtureEngine extends AutoBanEngine {
    public array $bans=[];
    public function executeBan(array $s,?int $admin=null): bool {
        if(empty($s['_evidence_validated'])||empty($s['_native_validated'])||$s['confidence']<90)throw new RuntimeException('Unsafe cached authority');
        $this->bans[]=$s['ip'];return true;
    }
}
$db=C::connection();if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');
$checks=0;function check($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
$db->beginTransaction();CycleBudget::begin(180,47);
try{
    if(getenv('AMSFB_TEST_SCHEMA')==='22')Database::setConfig('schema_version','22');
    C::table('mod_amssoft_fail2ban_ai_suggestions')->update(['classification'=>'monitor']);
    foreach(['ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold','ai_auto_create_filter'=>'0','ai_cached_decision_cursor'=>'0','ai_history_validation_per_cycle'=>'10',
        'ai_behavior_min_events'=>'3','ai_behavior_min_ips'=>'2','ai_behavior_enabled'=>'1','ai_behavior_require_repetition'=>'0','ai_threshold_high'=>'2:60'] as $k=>$v)Database::setConfig($k,$v);
    $source='/var/log/cached-'.bin2hex(random_bytes(8)).'.log';$ids=[];$fingerprints=[];$tasks=[];
    for($n=1;$n<=6;$n++){
        $ip='198.18.20.'.$n;$time=$n===4?time()-259200:time();
        $line=$ip.' - - ['.date('d/M/Y:H:i:s O',$time).'] "GET /wp-admin/ HTTP/1.1" 403 10 "-" "fixture"';
        if($n===5)$line=str_replace($ip,'198.18.20.99',$line);
        if($n===6)$line=str_replace('/wp-admin/','/clientarea.php',$line);
        $task=hash('sha256',$source.$n);$pattern=BehaviorStore::pattern($line);$tasks[]=$task;
        C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$task,'ip'=>$ip,'source_log'=>$source,'pattern'=>$pattern,'family_key'=>'wordpress-probe','bucket'=>date('Y-m-d H:i:s'),'events'=>1,'revision'=>1,'samples'=>json_encode([['line'=>$line]]),
            'processing_state'=>'review','attempts'=>5,'total_attempts'=>7,'validation_attempts'=>3,'total_validation_attempts'=>9]);
        $id=Database::saveSuggestion(['ip'=>$ip,'source_log'=>$source,'action'=>'ban','severity'=>'high','confidence'=>99,'evidence'=>[$line],'_pattern'=>$pattern,'_task_id'=>$task,
            '_analysis_key'=>hash('sha256',$task),'filter_name'=>'fixture','failregex'=>'^<HOST> attack$']);
        $ids[]=$id;$fp=hash('sha256',$source.'event'.$n);$fingerprints[]=$fp;
        C::table('mod_amssoft_fail2ban_detections')->insert(['fingerprint'=>$fp,'event_id'=>$fp,'ip'=>$ip,'source_log'=>$source,'suggestion_id'=>$id,'evidence'=>$line,'detected_at'=>date('Y-m-d H:i:s'),'pattern'=>$pattern,'confidence'=>'99']);
        if(\AMS\Fail2Ban\EvidenceLinks::enabled())\AMS\Fail2Ban\EvidenceLinks::link($fp,$id,['confidence'=>99],'unknown','legacy_current');
    }
    $engine=new CachedFixtureEngine(null,new Fail2BanClient);$metrics=HistoricalDecisions::tick($engine,new Fail2BanClient,'threshold');
    check($metrics['validated']===4&&$metrics['refused']===2,'Historical native validation partition');
    check($metrics['blocked']===2&&$engine->bans===['198.18.20.2','198.18.20.3'],'Only fresh, individual unprotected peers may be banned');
    check(Database::getSuggestion($ids[0])['decision_code']==='protected_existing','Existing native protection not recognized');
    check(Database::getSuggestion($ids[0])['status']==='pending','Protection rewrote decision status');
    check(Database::getSuggestion($ids[3])['status']==='pending','Stale proof authorized current ban');
    check(strtotime(C::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$fingerprints[3])->value('detected_at'))<time()-172800,'Old event manufactured as recent');
    foreach([4,5] as $index){
        $table=\AMS\Fail2Ban\EvidenceLinks::enabled()?\AMS\Fail2Ban\EvidenceLinks::TABLE:'mod_amssoft_fail2ban_detections';
        check(C::table($table)->where('fingerprint',$fingerprints[$index])->value('validation_state')==='invalid','Forged/nonmatching proof became valid');
    }
    foreach($tasks as $task){$r=C::table('mod_amssoft_fail2ban_rollups')->where('id',$task)->first();check($r->processing_state==='review'&&(int)$r->total_attempts===7&&(int)$r->total_validation_attempts===9,'Local validation reset task history');}
    $second=HistoricalDecisions::tick($engine,new Fail2BanClient,'threshold');
    check($second['validated']===0&&$second['refused']===0,'Same failed generation revalidated indefinitely');
    check(!array_diff(Privileged::$calls,['normalize-filter','ban-coverage']),'Local replay invoked other privileged operations');
}finally{CycleBudget::end();$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} cached historical decision checks; SQL rolled back, native/ban collaborators mocked, no provider\n";
}
