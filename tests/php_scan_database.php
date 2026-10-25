<?php
namespace AMS\Fail2Ban {
class Privileged {
    public static array $protected=[];public static bool $available=true;
    public static function run($args){
        if($args[0]==='protection-snapshot')return ['success'=>self::$available,'stable'=>self::$available,'observed_at'=>time(),'errors'=>[],
            'requirements'=>['http'=>[80,443]],'entries'=>array_map(fn($ip)=>['ip'=>$ip,'effective'=>true,'protocol'=>'tcp','ports'=>[80,443],'jail'=>'fixture','ticket'=>'fixture','expires_at'=>time()+3600],self::$protected)];
        if($args[0]==='normalize-filter'){$p=json_decode(file_get_contents($args[1]),true);return ['success'=>true,'patterns'=>$p['patterns'],'matched_sha256'=>array_map(fn($line)=>hash('sha256',$line),$p['evidence'])];}
        if(in_array($args[0],['ensure-ai-jail','validate-filter'],true))return ['success'=>true];
        throw new \RuntimeException('Unexpected native/provider operation: '.$args[0]);
    }
}
class Fail2BanClient {public array $bans=[];public function hasEffectiveBan($j,$ip){return isset($this->bans[$ip]);}public function banIP($j,$ip){$this->bans[$ip]=$j;return true;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,Policy,PhpScan,BehaviorStore,AnalysisWork,DecisionEligibility,DecisionProtection,EvidenceLinks,AutoBanEngine,AIAnalyzer,Fail2BanClient,Privileged};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');
$db->beginTransaction();$checks=0;$tmp=null;
function phpDbCheck($v,$why){global $checks;if(!$v)throw new RuntimeException($why);$checks++;}
function scanLine($ip,$path,$status=404,$time=null){return $ip.' - - ['.date('d/M/Y:H:i:s O',$time??time()-10).'] "GET '.$path.' HTTP/1.1" '.$status.' 10 "-" "fixture"';}
function scanDecision($ip,$paths,$confidence=99,$source='/var/log/apache2/access_whmcs.log',$status=404,$age=10,$cited=null){
    $events=[];foreach($paths as $i=>$path){$line=scanLine($ip,$path,$status,time()-$age+$i);$events[]=['id'=>hash('sha256',random_bytes(8)),'ip'=>$ip,'line'=>$line,'time'=>BehaviorStore::eventTime($line),'pattern'=>PhpScan::pattern()];}
    $s=['ip'=>$ip,'source_log'=>$source,'classification'=>'ban','action'=>'ban','severity'=>'high','confidence'=>$confidence,
        'filter_name'=>'fixture','failregex'=>'^<HOST> - \S+ \[\s*\] "GET (?:'.implode('|',array_map(fn($p)=>preg_quote($p,'~'),array_unique($paths))).') HTTP/1\.1" '.$status.' \d+',
        'evidence'=>array_slice(array_column($events,'line'),0,$cited??count($events)),'_pattern'=>PhpScan::pattern(),'_events'=>$events,
        '_native_validated'=>true,'_evidence_validated'=>true,'_analysis_key'=>hash('sha256',random_bytes(8)),'_task_id'=>hash('sha256',random_bytes(8))];
    $s['id']=$s['_suggestion_id']=Database::saveSuggestion($s);Database::recordDetections($s['id'],$s);return $s;
}
class PhpWorkerAI extends AIAnalyzer {
    public int $calls=0;public string $action='ban';public array $context=[];
    public function analyzeSubjects(array $lines,array $context):array{
        $this->requestStarting();$this->calls++;$this->context=$context;$out=[];
        foreach($context as $ip=>$ctx){
            $own=array_values(array_filter($lines,fn($line)=>\AMS\Fail2Ban\Safety::sourceIp($line)===$ip&&PhpScan::target($line)!==null));
            $paths=array_unique(array_map(fn($line)=>\AMS\Fail2Ban\RequestEvidence::target($line),$own));
            $out[]=['ip'=>$ip,'action'=>$this->action,'severity'=>'high','confidence'=>99,'threat'=>'fixture PHP scan',
                'filter_name'=>'fixture','evidence'=>$own,
                'failregex'=>'^<HOST> - \S+ \[\s*\] "GET (?:'.implode('|',array_map(fn($p)=>preg_quote($p,'~'),$paths)).') HTTP/1\.1" (?:403|404) \d+'];
        }return $out;
    }
}
try{
    Database::setConfig('schema_version','33');
    foreach(PhpScan::KEYS as $key)Database::setConfig($key,(string)Policy::fields()[$key][2]);
    foreach(['ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold','ai_auto_min_confidence'=>'90','ai_threshold_high'=>'100:60',
        'ai_behavior_enabled'=>'0','ai_individual_probe_enabled'=>'0','ai_history_validation_per_cycle'=>'0','ai_auto_create_filter'=>'0',
        'ai_review_auto_recovery_enabled'=>'0','ai_rule_requests'=>'{}','ai_whitelist_ips'=>'','ai_cycle_max_calls'=>'1','ai_cycle_seconds'=>'90'] as $key=>$value)Database::setConfig($key,$value);
    C::table('mod_amssoft_fail2ban_ai_suggestions')->update(['classification'=>'monitor']);
    C::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>C::raw('revision')]);
    C::table(AnalysisWork::BATCH_TABLE)->update(['status'=>'complete']);
    $paths=['/wp-filemanager1.php','/wp-security.php?p=','/randommalicious.php'];
    $s=scanDecision('198.18.91.1',$paths);$e=DecisionEligibility::evaluate($s);
    phpDbCheck($e['eligible']&&$e['reason']==='individual_php_scan'&&$e['php_scan']['targets']===3,'Three exact proofs not actionable');
    $client=new Fail2BanClient;phpDbCheck((new AutoBanEngine(null,$client))->executeBan($s)&&isset($client->bans[$s['ip']]),'Engine did not apply eligible fake ban');
    $two=scanDecision('198.18.91.2',array_slice($paths,0,2));Database::setConfig('ai_mode','auto');
    phpDbCheck(!DecisionEligibility::evaluate($two)['eligible'],'Auto bypassed PHP minimum');
    Database::setConfig('ai_threshold_high','1:60');phpDbCheck(!DecisionEligibility::evaluate($two)['eligible'],'Old threshold bypassed PHP minimum');
    Database::setConfig('ai_mode','threshold');
    $redirect=scanDecision('198.18.91.3',$paths,99,'/var/log/apache2/access_whmcs.log',301);
    phpDbCheck(!DecisionEligibility::evaluate($redirect)['eligible'],'Redirect-only scan authorized ban');
    $same=scanDecision('198.18.91.4',['/randommalicious.php?a=1','/randommalicious.php?a=2','/%72andommalicious.php']);
    phpDbCheck(!DecisionEligibility::evaluate($same)['eligible'],'Query variants inflated diversity');
    $low=scanDecision('198.18.91.5',$paths,89);phpDbCheck(!DecisionEligibility::evaluate($low)['eligible'],'Low confidence authorized ban');
    $uncited=scanDecision('198.18.91.6',$paths,99,'/var/log/apache2/access_whmcs.log',404,10,1);
    phpDbCheck(!DecisionEligibility::evaluate($uncited)['eligible'],'Uncited events granted authority');
    $other=scanDecision('198.18.91.7',[$paths[0]]);phpDbCheck(!DecisionEligibility::evaluate($other)['eligible'],'Foreign IP evidence inherited');
    $origin=scanDecision($s['ip'],[$paths[0]],99,'/var/log/apache2/access_license_gateway.log');
    phpDbCheck(!DecisionEligibility::evaluate($origin)['eligible'],'Another source inherited proofs');
    $old=scanDecision('198.18.91.8',$paths,99,'/var/log/apache2/access_whmcs.log',404,3600);
    phpDbCheck(DecisionEligibility::evaluate($old)['view']==='history','Expired scan eligible');
    $monitor=$s;$monitor['classification']='monitor';phpDbCheck(!DecisionEligibility::evaluate($monitor)['eligible'],'Monitor became ban');
    Database::setConfig('ai_php_scan_enabled','0');Database::setConfig('ai_mode','auto');
    phpDbCheck(!DecisionEligibility::evaluate($s)['eligible'],'Disabled gate fell back to auto');
    Database::setConfig('ai_php_scan_enabled','1');Database::setConfig('ai_mode','threshold');
    C::table(EvidenceLinks::TABLE)->where('suggestion_id',$s['id'])->update(['validation_context_hash'=>'wrong']);
    phpDbCheck(!DecisionEligibility::phpScan($s)['eligible'],'Stale proof context counted');
    C::table(EvidenceLinks::TABLE)->where('suggestion_id',$s['id'])->update(['validation_context_hash'=>DecisionEligibility::contextHash()]);
    C::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$s['id'])->update(['status'=>'rejected']);
    phpDbCheck(!DecisionEligibility::phpScan($s)['eligible'],'Rejected evidence counted');
    // Reproduce a coherent 43-path scan in private logs, never in production logs.
    $ip='198.18.91.20';$lines=[];$base=(int)(floor(time()/600)*600)-590;
    for($i=0;$i<43;$i++)foreach([301,404] as $status)$lines[]=scanLine($ip,'/probe'.$i.'.php',$status,$base+$i*2);
    $tmp=tempnam('/tmp','amsfb_php_scan_');file_put_contents($tmp,implode("\n",$lines)."\n");$stat=stat($tmp);
    Database::setConfig('adaptive_cursor.'.md5($tmp),json_encode(['file'=>$stat['dev'].':'.$stat['ino'],'generation'=>'fixture','offset'=>0,'anchor'=>'','draining'=>false]));
    $collected=BehaviorStore::collect($tmp);
    $rows=C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$tmp)->get()->map(fn($r)=>(array)$r)->all();
    phpDbCheck($collected['events']===86&&count($rows)===1,'Collector fragmented coherent PHP scan');
    $samples=json_decode($rows[0]['samples'],true);phpDbCheck(PhpScan::stats($samples,$ip,time()-1800)===['events'=>5,'targets'=>5],'Distinct failed evidence lost');
    $row=$rows[0];$row['id']=hash('sha256',random_bytes(8));$row['source_log']='/var/log/apache2/access_whmcs.log';$row['analyzed_revision']=0;
    C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$tmp)->update(['analyzed_revision'=>C::raw('revision')]);
    C::table('mod_amssoft_fail2ban_rollups')->insert($row);
    phpDbCheck(in_array($row['id'],array_column(BehaviorStore::pending(5000,null,true),'id'),true),'Diverse group lost urgent priority');
    $ai=new PhpWorkerAI('openai','fixture');$workerClient=new Fail2BanClient;(new AutoBanEngine($ai,$workerClient))->runAnalysis();
    phpDbCheck($ai->calls===1&&($ai->context[$ip]['php_scan']['targets']??0)===5,'Worker context/grouping failed');
    phpDbCheck(isset($workerClient->bans[$ip]),'Full worker failed validated PHP ban');
    foreach(['monitor','protected','unknown'] as $case){
        $row['id']=hash('sha256',random_bytes(8));$row['ip']='198.18.91.'.(['monitor'=>21,'protected'=>22,'unknown'=>23][$case]);$row['analyzed_revision']=0;
        $newSamples=$samples;foreach($newSamples as &$event){$event['ip']=$row['ip'];$event['id']=hash('sha256',random_bytes(8));$event['line']=str_replace($ip,$row['ip'],$event['line']);}unset($event);
        $row['samples']=json_encode($newSamples);C::table('mod_amssoft_fail2ban_rollups')->insert($row);
        if($case==='protected')Privileged::$protected=[$row['ip']];
        if($case==='unknown')Privileged::$available=false;
        \AMS\Fail2Ban\BlockedTasks::refresh(true);
        $ai=new PhpWorkerAI('openai','fixture');$ai->action='monitor';$client=new Fail2BanClient;(new AutoBanEngine($ai,$client))->runAnalysis();
        phpDbCheck($client->bans===[]&&$ai->calls===($case==='monitor'?1:0),'Monitor/protected/unknown policy failed: '.$case);
        C::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->update(['analyzed_revision'=>C::raw('revision')]);
        Privileged::$protected=[];Privileged::$available=true;
    }
    Database::setConfig('schema_version','32');Database::setConfig('schema32_complete','1');Database::setConfig('schema33_complete','0');
    Database::setConfig('ai_php_scan_enabled','0');Database::setConfig('native_probe_groups','env');
    $db->enableQueryLog();\AMS\Fail2Ban\Migrations::run();
    phpDbCheck(Database::getConfig('schema_version')===(string)\AMS\Fail2Ban\Migrations::VERSION&&Database::getConfig('ai_php_scan_enabled')==='0'&&Database::getConfig('native_probe_groups')==='env','Migration changed operator selection');
    foreach($db->getQueryLog() as $query)phpDbCheck(!preg_match('/^\s*(create|alter|drop|truncate)/i',$query['query']),'Schema33 issued DDL');
}finally{if($tmp&&is_file($tmp))unlink($tmp);DecisionProtection::reset();$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} PHP scan collector/proof/worker checks; SQL rolled back; fake provider/native/bans\n";
}
