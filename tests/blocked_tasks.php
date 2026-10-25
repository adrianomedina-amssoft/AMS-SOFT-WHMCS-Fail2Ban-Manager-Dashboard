<?php
namespace AMS\Fail2Ban {
    // Only read-only collaborators are faked. SQL and eligibility code are real.
    class Privileged {
        public static array $coverage=[];public static string $path='';public static ?\Closure $read=null;
        public static function run(array $args): array {
            if($args[0]==='ban-coverage')return self::$read?(self::$read)():self::$coverage;
            if($args[0]==='effective-config')return ['success'=>true,'jails'=>['fixture'=>['logpath'=>self::$path]]];
            return ['success'=>true,'output'=>''];
        }
    }
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule;
use AMS\Fail2Ban\{Database,BlockedTasks,BehaviorStore,Policy,Privileged,AutoBanEngine,AIAnalyzer,Fail2BanClient,QueueTelemetry,CycleAcceptance,Safety};
$c=new Capsule();$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
class BlockedFixtureAI extends AIAnalyzer {
    public int $calls=0;public array $seen=[];
    public function analyzeSubjects(array $lines,array $context): array {
        $this->requestStarting();$this->calls++;$this->seen=$lines;$out=[];
        foreach($lines as $line){$ip=Safety::sourceIp($line);$out[$ip]=['ip'=>$ip,'action'=>'monitor','confidence'=>99,'severity'=>'low','threat'=>'fixture','evidence'=>[$line],'filter_name'=>'','failregex'=>''];}
        return array_values($out);
    }
}
$checks=0;function check($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
$db=Capsule::connection();if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy; retry');
$db->beginTransaction();$temporary=tempnam('/var/log','amsfb-blocked-');$path=$temporary.'.log';rename($temporary,$path);
Database::setConfig('schema_version','23'); // Legacy optional overlay contract; schema24 cannot disable exclusion.
Database::setConfig('ai_rule_requests','{}');Database::setConfig('ai_history_validation_per_cycle','0');
try {
    Capsule::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>Capsule::raw('revision')]);
    foreach(['ai_skip_effectively_banned'=>'1','ai_blocked_recheck_seconds'=>'300','ai_auto_enabled'=>'1','ai_mode'=>'suggestion','ai_cycle_max_calls'=>'1','ai_auto_create_filter'=>'0','ai_whitelist_ips'=>'','ai_cycle_metrics'=>'[]'] as $k=>$v)Database::setConfig($k,$v);
    $ip='198.51.100.231';$line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET /.env HTTP/1.1" 404 10 "-" "scanner"';
    file_put_contents($path,$line."\n");Privileged::$path=$path;BehaviorStore::collect($path);file_put_contents($path,$line."\n",FILE_APPEND);BehaviorStore::collect($path);
    $row=fn()=>(array)Capsule::table('mod_amssoft_fail2ban_rollups')->where('source_log',$path)->first();$r=$row();
    $set=fn($v)=>Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$r['id'])->update($v);
    $entry=['ip'=>$ip,'effective'=>true,'protocol'=>'tcp','ports'=>[80,443],'jail'=>'native-http','ticket'=>'unchanged-identity','expires_at'=>time()+3600];
    $snapshot=['success'=>true,'observed_at'=>time(),'entries'=>[$entry],'ttl'=>300];Privileged::$coverage=$snapshot;
    check(BlockedTasks::protection($r,$snapshot)!==null,'HTTP scope confirmed');
    foreach(['ports'=>[22],'effective'=>false,'expires_at'=>time()-1,'protocol'=>'udp'] as $key=>$value){$bad=$snapshot;$bad['entries'][0][$key]=$value;check(BlockedTasks::protection($r,$bad)===null,'Unsafe coverage refused: '.$key);}
    $bad=$snapshot;$bad['success']=false;check(BlockedTasks::protection($r,$bad)===null,'Unknown coverage not trusted');
    $bad=$snapshot;$bad['observed_at']=time()-301;check(BlockedTasks::protection($r,$bad)===null,'Expired cache not trusted');
    $bad=$r;$bad['samples']=json_encode([['line'=>'unknown format from '.$ip]]);check(BlockedTasks::protection($bad,$snapshot)===null,'Unknown service stays eligible');
    $both=$snapshot;$both['entries'][0]['ports']=[80];$both['entries'][]=array_replace($entry,['jail'=>'second-http','ports'=>[443]]);
    check(BlockedTasks::protection($r,$both)!==null,'Separate confirmed jails can cover both HTTP ports');
    $set(['processing_state'=>'review','validation_attempts'=>2,'attempts'=>4,'retry_at'=>date('Y-m-d H:i:s',time()+600),'failure_code'=>'filter_positive']);
    BlockedTasks::refresh(true);$held=$row();
    check($held['processing_state']==='review'&&(int)$held['validation_attempts']===2&&(int)$held['attempts']===4,'Suspension preserves review and attempts');
    check($held['retry_at']!==null&&$held['blocked_confirmed_at']!==null,'Suspension preserves backoff and records proof');
    check(BehaviorStore::recoverReviews()===0,'Held review spends no recovery round');
    file_put_contents($path,$line."\n",FILE_APPEND);BehaviorStore::collect($path);
    check($row()['blocked_by_json']===$held['blocked_by_json']&&$row()['processing_state']==='review','Collection preserves suspension and review');
    $set(['processing_state'=>'pending','attempts'=>0,'retry_at'=>null]);
    check(!in_array($r['id'],array_column(BehaviorStore::pending(100),'id'),true),'Held task excluded from automatic selection');
    check(BlockedTasks::filterLines([$line])===[],'Held task excluded from manual lines');
    $ai=new BlockedFixtureAI('openai','fixture');$engine=new AutoBanEngine($ai,new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client'));
    $engine->runAnalysis();$metrics=QueueTelemetry::summary()['last'];$state=QueueTelemetry::summary()['state'];
    check($ai->calls===0&&$metrics['calls']===0&&$metrics['reason']==='all_candidates_blocked','All protected means zero API calls');
    check((int)$row()['analyzed_revision']===0,'Suspension is not an acknowledgement');
    $coverage=['coverage_version'=>4,'active_jails'=>1,'missing_jail_tickets'=>0,'missing_f2b_rules'=>0,'orphan_firewall_ips'=>0,'duplicate_prefix_jails'=>0,'jails_without_actions'=>[],'jails_unverified'=>[]];
    check(CycleAcceptance::valid($metrics,$state,$coverage,$metrics['finished_at'],0,0,'',['calls'=>10,'seconds'=>180,'retry_percent'=>30]),'Zero-call protected cycle can pass explicit acceptance');
    $invalid=$metrics;$invalid['blocked']['confirmed']=false;
    check(!CycleAcceptance::valid($invalid,$state,$coverage,$metrics['finished_at'],0,0,'',['calls'=>10,'seconds'=>180,'retry_percent'=>30]),'Unknown protection cannot pass zero-call acceptance');
    $engine->analyzePathManual($path);check($ai->calls===0,'Manual analysis also makes zero API calls for protected lines');
    $set(['blocked_confirmed_at'=>null,'blocked_until_check_at'=>null,'blocked_by_json'=>null]);
    $reads=0;Privileged::$read=function()use(&$reads,$snapshot){$reads++;return $reads<3?['success'=>true,'observed_at'=>time(),'entries'=>[]]:$snapshot;};
    $engine->runAnalysis();check($ai->calls===0&&$row()['blocked_confirmed_at']!==null,'New block during preparation prevents transport and attempts');
    Privileged::$read=null;
    Privileged::$coverage=['success'=>false,'error'=>'Injected read failure'];BlockedTasks::refresh(true);
    check($row()['blocked_confirmed_at']===null&&BlockedTasks::health()['error']!=='','Read failure releases trust, not evidence');
    Privileged::$coverage=$snapshot;Privileged::$coverage['entries'][0]['expires_at']=time()-1;BlockedTasks::refresh(true);
    check($row()['blocked_confirmed_at']===null,'Expired ticket releases suspension');
    Privileged::$coverage=$snapshot;BlockedTasks::refresh(true);Privileged::$coverage['entries']=[];BlockedTasks::refresh(true);
    check($row()['blocked_confirmed_at']===null,'Unban/lost rule releases suspension');
    $engine->runAnalysis();check($ai->calls===1&&(int)$row()['analyzed_revision']===(int)$row()['revision'],'Unprotected task resumes and completes normally');
    $set(['analyzed_revision'=>0]);Privileged::$coverage=$snapshot;BlockedTasks::refresh(true);
    Database::setConfig('ai_skip_effectively_banned','0');BlockedTasks::refresh(true);
    check($row()['blocked_confirmed_at']===null&&count(BehaviorStore::pending(10))===1,'UI disable safely restores eligibility without ban changes');
    Database::setConfig('ai_skip_effectively_banned','1');$set(['bucket'=>date('Y-m-d H:i:s',time()-90000)]);BlockedTasks::refresh(true);
    check(!in_array($r['id'],array_column(BehaviorStore::pending(10),'id'),true),'Expired evidence never reenters eligible queue');
    foreach(['ai_skip_effectively_banned','ai_blocked_recheck_seconds'] as $key)check(isset(Policy::fields()[$key]),'Policy field shared with UI/runtime');
    Privileged::$coverage=$snapshot;$unblocked=str_replace($ip,'198.51.100.232',$line);file_put_contents($path,$unblocked."\n",FILE_APPEND);
    $before=$ai->calls;$engine->analyzePathManual($path);
    check($ai->calls===$before+1&&$ai->seen&&count(array_filter($ai->seen,fn($l)=>Safety::sourceIp($l)!=='198.51.100.232'))===0,'Mixed manual request sends only unprotected peer to API');
} finally {Privileged::$read=null;BlockedTasks::invalidate();$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");unlink($path);}
echo "PASS: {$checks} blocked-task checks; fake read-only coverage/API, SQL rolled back\n";
}
