<?php
namespace AMS\Fail2Ban {
class Privileged {public static array $snapshot=['success'=>true,'stable'=>true,'errors'=>[],'entries'=>[],'requirements'=>['http'=>[80,443],'ssh'=>[2222]]];public static array $calls=[];
public static function run($a){self::$calls[]=$a[0];if($a[0]==='protection-snapshot')return self::$snapshot+['observed_at'=>time()];
if($a[0]==='normalize-filter'){$p=json_decode(file_get_contents($a[1]),true);return ['success'=>true,'patterns'=>$p['patterns'],'matched_sha256'=>array_map(fn($l)=>hash('sha256',$l),$p['evidence'])];}
if(in_array($a[0],['ensure-ai-jail','validate-filter'],true))return ['success'=>true];
throw new \RuntimeException('Native mutation/API forbidden: '.$a[0]);}}
class Fail2BanClient {public array $bans=[];public function hasEffectiveBan($j,$ip){return isset($this->bans[$ip]);}public function banIP($j,$ip){$this->bans[$ip]=$j;return true;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{Database,Policy,RecentActivity,DecisionEligibility,DecisionProtection,SensitiveTargets,BehaviorStore,EvidenceLinks,AutoBanEngine,AIAnalyzer,Fail2BanClient,Privileged};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
if(!C::schema()->hasColumn('mod_amssoft_fail2ban_rollups','last_event_at'))throw new RuntimeException('Provision metadata explicitly; no DDL in fixture');
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy; retry');
$db->beginTransaction();$n=0;$nonce=bin2hex(random_bytes(8));function ok($v,$why){global $n;if(!$v)throw new RuntimeException($why);$n++;}
class RecentWorkerAI extends AIAnalyzer {
 public int $calls=0;
 public function analyzeSubjects(array $lines,array $context): array {$this->requestStarting();$this->calls++;$out=[];
  foreach($context as $ip=>$ctx)$out[]=['ip'=>$ip,'action'=>'monitor','severity'=>'low','confidence'=>99,'threat'=>'fixture',
   'filter_name'=>'','failregex'=>'','evidence'=>array_values(array_filter($lines,fn($l)=>\AMS\Fail2Ban\Safety::sourceIp($l)===$ip))];return $out;}
}
function lineFor($ip,$target,$t){return $ip.' - - ['.date('d/M/Y:H:i:s O',$t).'] "GET '.$target.' HTTP/1.1" 404 10 "-" "fixture"';}
function decision($ip,$target,$t,$source='/var/log/apache2/access_whmcs.log',$confidence=99){
 global $nonce;$line=lineFor($ip,$target,$t);$pattern=BehaviorStore::pattern($line);$event=['id'=>hash('sha256',$nonce.$ip.$line.$source),'ip'=>$ip,'line'=>$line,'time'=>$t,'pattern'=>$pattern];
 $s=['ip'=>$ip,'source_log'=>$source,'action'=>'ban','classification'=>'ban','severity'=>'high','confidence'=>$confidence,'evidence'=>[$line],
 'filter_name'=>'fixture','failregex'=>'^<HOST> fixture','_evidence_validated'=>true,'_native_validated'=>true,'_pattern'=>$pattern,'_events'=>[$event],
 '_analysis_key'=>hash('sha256',$nonce.$ip.$line.$source),'_task_id'=>hash('sha256',$nonce.$line)];
 $id=Database::saveSuggestion($s);$s['id']=$s['_suggestion_id']=$id;Database::recordDetections($id,$s);return $s;
}
try{
 Database::setConfig('schema_version','25');
 C::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>C::raw('revision')]);
 C::table(\AMS\Fail2Ban\AnalysisWork::BATCH_TABLE)->update(['status'=>'complete']);
 C::table('mod_amssoft_fail2ban_ai_suggestions')->update(['classification'=>'monitor']);
 foreach(['ai_analysis_recent_minutes'=>'30','ai_individual_probe_enabled'=>'1','ai_individual_probe_min_confidence'=>'90','ai_individual_probe_min_events'=>'3','ai_individual_probe_min_targets'=>'2','ai_individual_probe_window_minutes'=>'60',
 'ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold','ai_auto_min_confidence'=>'90','ai_threshold_high'=>'2:60','ai_behavior_enabled'=>'1','ai_behavior_require_repetition'=>'0','ai_behavior_min_events'=>'3','ai_behavior_min_ips'=>'2','ai_behavior_hours'=>'24','ai_auto_create_filter'=>'0','ai_whitelist_ips'=>''] as $k=>$v)Database::setConfig($k,$v);
 $ip='198.18.61.1';$first=decision($ip,'/.env',time()-40);
 ok(DecisionEligibility::evaluate($first)['view']==='waiting','Single probe should wait');
 ok(DecisionEligibility::own($first)!==[],'Exact current own link lost');
 $second=decision($ip,'/.ssh/id_rsa',time()-30);$third=decision($ip,'/.git/HEAD',time()-20);
 ok(DecisionEligibility::individual($third)['eligible'],'Three events/two sensitive targets should qualify one IP');
 ok(DecisionEligibility::evaluate($third)['view']==='actionable','Individual proof not actionable');
 $client=new Fail2BanClient;$engine=new AutoBanEngine(null,$client);
 ok($engine->executeBan($third)&&count($client->bans)===1,'Eligible fixture failed fake ban');
 Privileged::$snapshot['entries']=[['ip'=>$ip,'jail'=>'existing','ticket'=>'same','expires_at'=>time()+3600,'protocol'=>'tcp','ports'=>[80,443],'effective'=>true]];
 ok($engine->approveSuggestion($third['id'],1)&&count($client->bans)===1,'Existing protection renewed ban');
 Privileged::$snapshot['entries']=[];
 C::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$first['_events'][0]['id'])->update(['validation_state'=>'rejected']);
 ok(!DecisionEligibility::individual($third)['eligible'],'Rejected physical event counted');
 C::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$first['_events'][0]['id'])->update(['validation_state'=>'valid']);
 C::table(EvidenceLinks::TABLE)->where('suggestion_id',$first['id'])->update(['confidence'=>89]);
 ok(!DecisionEligibility::individual($third)['eligible'],'Low association confidence counted');
 C::table(EvidenceLinks::TABLE)->where('suggestion_id',$first['id'])->update(['confidence'=>99,'validation_context_hash'=>'wrong']);
 ok(!DecisionEligibility::individual($third)['eligible'],'Stale native context counted');
 C::table(EvidenceLinks::TABLE)->where('suggestion_id',$first['id'])->update(['validation_context_hash'=>DecisionEligibility::contextHash()]);
 C::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$first['id'])->update(['failregex'=>'changed']);
 ok(!DecisionEligibility::individual($third)['eligible'],'Changed regex retained authority');
 C::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$first['id'])->update(['failregex'=>$first['failregex']]);
 $foreign=decision('198.18.61.2','/.env',time()-10);ok(!DecisionEligibility::individual($foreign)['eligible'],'Another IP inherited evidence');
 $origin=decision($ip,'/.env',time()-9,'/var/log/apache2/access_license_gateway.log');ok(!DecisionEligibility::individual($origin)['eligible'],'Another origin inherited evidence');
 $low=decision('198.18.61.3','/.env',time()-8,'/var/log/apache2/access_whmcs.log',89);ok(!DecisionEligibility::evaluate($low)['eligible'],'Low classification confidence admitted');
 $old=decision('198.18.61.4','/.env',time()-7200);ok(DecisionEligibility::evaluate($old)['view']==='history','Old evidence not historical');
 $newLine=lineFor($old['ip'],'/.env',time());$task=hash('sha256',$nonce.'new');
 C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$task,'ip'=>$old['ip'],'source_log'=>$old['source_log'],'pattern'=>$old['_pattern'],'bucket'=>date('Y-m-d H:i:s'),'last_event_at'=>date('Y-m-d H:i:s'),'events'=>1,'revision'=>1,'samples'=>json_encode([['id'=>hash('sha256',$task),'ip'=>$old['ip'],'pattern'=>$old['_pattern'],'time'=>time(),'line'=>$newLine]])]);
 ok(DecisionEligibility::evaluate($old)['view']==='checking'&&!$engine->approveSuggestion($old['id'],1),'New activity revived old ban authority');
 ok(RecentActivity::filterLines([$old['evidence'][0],$newLine])===[$newLine],'Paid cold filter failed');
 $ai=new AIAnalyzer('openai','fixture');$before=count(Privileged::$calls);
 ok($ai->analyze([$old['evidence'][0]])===[]&&$ai->generateFilterRegex([$old['evidence'][0]])===null,'Cold manual/filter request reached API');
 ok(count(Privileged::$calls)===$before,'Cold request invoked native/provider unnecessarily');
 $coldTask=hash('sha256',$nonce.'cold');
 C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$coldTask,'ip'=>$old['ip'],'source_log'=>$old['source_log'],'pattern'=>$old['_pattern'],'bucket'=>date('Y-m-d H:i:s',time()-7200),'last_event_at'=>date('Y-m-d H:i:s',time()-7200),'events'=>1,'revision'=>1,'samples'=>json_encode([['line'=>$old['evidence'][0]]])]);
 ok(!in_array($coldTask,array_column(BehaviorStore::pending(5000),'id'),true),'Cold task in paid ready pool');
 ok(in_array($task,array_column(BehaviorStore::pending(5000,null,true),'id'),true),'Recent sensitive task lost priority before AI classification');
 $cold=C::table('mod_amssoft_fail2ban_rollups')->where('id',$coldTask)->first();ok((int)$cold->analyzed_revision===0&&(int)$cold->total_attempts===0,'Cold task acknowledged or attempted');
 ok(SensitiveTargets::target(lineFor($ip,'/%2eenv?x=1',time()))===SensitiveTargets::target(lineFor($ip,'/a/.env?x=2',time())),'Encoding/query inflated target identity');
 ok(SensitiveTargets::target(lineFor($ip,'/.env.example',time()))===null,'Example env is sensitive target');
 ok(SensitiveTargets::target(lineFor($ip,'/retired-page',time()))===null,'Normal endpoint entered sensitive catalogue');
 $repeat='198.18.61.5';decision($repeat,'/.env',time()-3);decision($repeat,'/a/.env?x=1',time()-2);$repeatS=decision($repeat,'/%2eenv?x=2',time()-1);
 ok(!DecisionEligibility::individual($repeatS)['eligible'],'Same sensitive target variants counted as multiple targets');
 Database::setConfig('ai_whitelist_ips',$ip);ok(!DecisionEligibility::evaluate($third)['eligible'],'Whitelist ignored');Database::setConfig('ai_whitelist_ips','');
 Privileged::$snapshot=['success'=>false];ok(!$engine->approveSuggestion($third['id'],1),'Unknown protection authorized ban');
 $projection=DecisionProtection::refresh(Privileged::$snapshot);ok(count($projection['groups']['actionable'])===0,'Unknown query has actionable IDs');
 ok(Database::getPendingSuggestionsPaged(1,10)['total']===0&&Database::countPendingSuggestions()===0,'Unknown query counts disagree');
 Privileged::$snapshot=['success'=>true,'stable'=>true,'errors'=>[],'entries'=>[],'requirements'=>['http'=>[80,443]]];
 $projection=DecisionProtection::refresh(Privileged::$snapshot+['observed_at'=>time(),'ttl'=>300]);
 ok(in_array($third['id'],$projection['groups']['actionable'],true),'Live proof lost from projection');
 ok(!in_array($old['id'],Database::getPendingIdsByCountry(''),true),'Bulk selected old proof');
 ok(C::table(DecisionProtection::TABLE)->where('suggestion_id',$third['id'])->value('eligibility_reason')!==null,'Eligibility metadata not persisted');
 try{Policy::validate(['ai_individual_probe_min_events'=>'3','ai_individual_probe_min_targets'=>'4'],Policy::values());ok(false,'Invalid target count accepted');}catch(InvalidArgumentException $e){ok(true,'Cross validation');}
 C::table('mod_amssoft_fail2ban_ai_suggestions')->update(['classification'=>'monitor']);
 $cachedIp='198.18.61.6';decision($cachedIp,'/.env',time()-3);decision($cachedIp,'/.ssh/id_rsa',time()-2);decision($cachedIp,'/.git/HEAD',time()-1);
 foreach(['ai_behavior_require_repetition'=>'1','ai_threshold_high'=>'99:60','ai_history_validation_per_cycle'=>'10','ai_cached_decision_cursor'=>'0'] as $k=>$v)Database::setConfig($k,$v);
 $cachedClient=new Fail2BanClient;$cachedEngine=new AutoBanEngine(null,$cachedClient);
 $cached=\AMS\Fail2Ban\HistoricalDecisions::tick($cachedEngine,$cachedClient,'threshold');
 ok($cached['blocked']>0&&isset($cachedClient->bans[$cachedIp])&&count($cachedClient->bans)===1,'Cached individual criterion still required old threshold/campaign');
 foreach(['ai_cycle_max_calls'=>'1','ai_cycle_seconds'=>'90','ai_history_validation_per_cycle'=>'0','ai_review_auto_recovery_enabled'=>'0','ai_rule_requests'=>'{}'] as $k=>$v)Database::setConfig($k,$v);
 $workerAI=new RecentWorkerAI('openai','fixture');$worker=new AutoBanEngine($workerAI,$client);$worker->runAnalysis();
 ok($workerAI->calls===1,'Fresh worker task not admitted');
 ok((int)C::table('mod_amssoft_fail2ban_rollups')->where('id',$task)->value('analyzed_revision')===1,'Fresh worker task not finalized');
 $cold=C::table('mod_amssoft_fail2ban_rollups')->where('id',$coldTask)->first();
 ok((int)$cold->analyzed_revision===0&&(int)$cold->total_attempts===0,'Worker paid/acknowledged cold task');
 $worker->runAnalysis();ok($workerAI->calls===1,'Cold-only backlog called provider');
 Privileged::$snapshot['entries']=[['ip'=>$old['ip'],'jail'=>'existing','ticket'=>'same','expires_at'=>time()+3600,'protocol'=>'tcp','ports'=>[80,443],'effective'=>true]];
 ok(DecisionProtection::filterLines([$newLine])===[],'Already blocked IP reached paid line admission');
 Privileged::$snapshot['entries']=[];
 $future=C::table('mod_amssoft_fail2ban_rollups')->where('id',$task)->first();
 C::table('mod_amssoft_fail2ban_rollups')->where('id',$task)->update(['analyzed_revision'=>0,'retry_at'=>null]);
 Privileged::$snapshot=['success'=>false];$worker->runAnalysis();
 ok($workerAI->calls===1&&(int)C::table('mod_amssoft_fail2ban_rollups')->where('id',$task)->value('analyzed_revision')===0,'Unknown protection paid/acknowledged work');
}finally{DecisionProtection::reset();$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$n} schema25 eligibility/recent/individual checks; SQL rolled back, fake API/native bans\n";
}
