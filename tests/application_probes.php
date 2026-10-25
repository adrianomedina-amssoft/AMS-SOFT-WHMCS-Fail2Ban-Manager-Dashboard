<?php
namespace AMS\Fail2Ban {
class Privileged {public static array $protected=[];public static bool $available=true;public static function run($a){
 if($a[0]==='protection-snapshot')return ['success'=>self::$available,'stable'=>self::$available,'errors'=>[],'observed_at'=>time(),'requirements'=>['http'=>[80,443]],
 'entries'=>array_map(fn($ip)=>['ip'=>$ip,'effective'=>true,'protocol'=>'tcp','ports'=>[80,443],'jail'=>'fixture','ticket'=>'fixture','expires_at'=>time()+3600],self::$protected)];
 if($a[0]==='normalize-filter'){$p=json_decode(file_get_contents($a[1]),true);return ['success'=>true,'patterns'=>$p['patterns'],'matched_sha256'=>array_map(fn($l)=>hash('sha256',$l),$p['evidence'])];}
 if(in_array($a[0],['ensure-ai-jail','validate-filter'],true))return ['success'=>true];
 throw new \RuntimeException('Unexpected native/API operation '.$a[0]);}}
class Fail2BanClient {public array $bans=[];public function hasEffectiveBan($j,$ip){return isset($this->bans[$ip]);}public function banIP($j,$ip){$this->bans[$ip]=$j;return true;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{Database,Policy,ProbeApplications,BehaviorStore,AnalysisWork,DecisionEligibility,DecisionMemory,AutoBanEngine,AIAnalyzer,Fail2BanClient};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');$db->beginTransaction();$checks=0;$tmp=null;
function probeCheck($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
function probeLine($ip,$path,$t=null){return $ip.' - - ['.date('d/M/Y:H:i:s O',$t??time()).'] "GET '.$path.' HTTP/1.1" 404 10 "-" "fixture"';}
function probeDecision($ip,$paths,$confidence=99,$age=20,$source='/var/log/apache2/access_whmcs.log',$cited=null){
 $events=[];$pattern=ProbeApplications::pattern(ProbeApplications::groups());foreach($paths as $i=>$path){$line=probeLine($ip,$path,time()-$age+$i);$events[]=['id'=>hash('sha256',random_bytes(8)),'ip'=>$ip,'line'=>$line,'time'=>BehaviorStore::eventTime($line),'pattern'=>$pattern];}
 $s=['ip'=>$ip,'source_log'=>$source,'action'=>'ban','classification'=>'ban','severity'=>'high','confidence'=>$confidence,'evidence'=>array_slice(array_column($events,'line'),0,$cited??count($events)),'filter_name'=>'fixture',
 'failregex'=>'^<HOST> - \\S+ \\[\\s*\\] "GET (?:'.implode('|',array_map(fn($p)=>preg_quote($p,'~'),array_unique($paths))).') HTTP/1\\.1" 404 \\d+',
 '_pattern'=>$pattern,'_events'=>$events,'_native_validated'=>true,'_evidence_validated'=>true,'_analysis_key'=>hash('sha256',random_bytes(8)),'_task_id'=>hash('sha256',random_bytes(8))];
 $s['id']=$s['_suggestion_id']=Database::saveSuggestion($s);Database::recordDetections($s['id'],$s);return $s;
}
class ApplicationWorkerAI extends AIAnalyzer {public int $calls=0;public array $context=[];public string $action='ban';
 public function analyzeSubjects(array $lines,array $context):array{$this->requestStarting();$this->calls++;$this->context=$context;$result=[];foreach($context as $ip=>$ctx){
 $own=array_values(array_filter($lines,fn($l)=>\AMS\Fail2Ban\Safety::sourceIp($l)===$ip));$paths=array_unique(array_map(fn($l)=>\AMS\Fail2Ban\RequestEvidence::target($l),$own));
 $result[]=['ip'=>$ip,'action'=>$this->action,'severity'=>'high','confidence'=>99,'threat'=>'fixture applications','filter_name'=>'fixture',
 'failregex'=>'^<HOST> - \\S+ \\[\\s*\\] "GET (?:'.implode('|',array_map(fn($p)=>preg_quote($p,'~'),$paths)).') HTTP/1\\.1" 404 \\d+',
 'evidence'=>$own];}return $result;}}
try {
 Database::setConfig('schema_version','28');foreach(ProbeApplications::KEYS as $k)Database::setConfig($k,(string)Policy::fields()[$k][2]);
 foreach(['ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold','ai_auto_min_confidence'=>'90','ai_threshold_high'=>'100:60','ai_behavior_enabled'=>'0','ai_individual_probe_enabled'=>'0','ai_history_validation_per_cycle'=>'0','ai_auto_create_filter'=>'0','ai_review_auto_recovery_enabled'=>'0','ai_rule_requests'=>'{}','ai_whitelist_ips'=>''] as $k=>$v)Database::setConfig($k,$v);
 foreach(['/','/retired-page','/clientarea.php','/owa/not-the-target','/wp-content/theme.css','/index.php?url=/owa/'] as $path)probeCheck(ProbeApplications::application(probeLine('198.18.71.1',$path))===null,'Normal route in catalogue');
 probeCheck(ProbeApplications::application(probeLine('198.18.71.1','/owa/'))==='exchange','Application missing');
 probeCheck(ProbeApplications::application(probeLine('198.18.71.1','/owa/'),['wordpress'])===null,'Disabled application counted');
 foreach(['sitecore'=>'/sitecore/shell/sitecore.version.xml','solr'=>'/solr/admin/info/system','sugarcrm'=>'/sugar_version.json','qnap'=>'/cgi-bin/authLogin.cgi','spring'=>'/actuator/env','vmware'=>'/developmentserver/metadatauploader'] as $app=>$path){
  probeCheck(ProbeApplications::application(probeLine('2001:db8::71',$path))===$app,'Extended group missing '.$app);
  probeCheck(ProbeApplications::application(probeLine('198.18.71.1',$path),ProbeApplications::LEGACY_GROUPS)===null,'Unselected extended group counted');
 }
 foreach(['/mcp','/mcp/','/admin/login.php','/index.jsp','/console','/identity','/favicon.ico','/index.php?target=/solr/'] as $path)
  probeCheck(ProbeApplications::application(probeLine('198.18.71.1',$path))===null,'Generic endpoint entered catalogue');
 probeCheck(ProbeApplications::catalogPattern(ProbeApplications::pattern(ProbeApplications::LEGACY_GROUPS)),'Legacy application gate lost');
 probeCheck(ProbeApplications::catalogPattern(ProbeApplications::pattern(['solr','sugarcrm','servlet'])),'Extended subset gate missing');
 $two=probeDecision('198.18.71.1',['/owa/','/login.do']);probeCheck(!DecisionEligibility::evaluate($two)['eligible'],'Two apps authorized ban');
 Database::setConfig('ai_mode','auto');probeCheck(!DecisionEligibility::evaluate($two)['eligible'],'Auto bypassed minimum applications');Database::setConfig('ai_mode','threshold');
 $s=probeDecision('198.18.71.2',['/owa/','/Telerik.Web.UI.WebResource.axd','/login.do']);$e=DecisionEligibility::evaluate($s);
 probeCheck($e['eligible']&&$e['reason']==='individual_application_probe','Three proved apps not actionable');
 $client=new Fail2BanClient;$engine=new AutoBanEngine(null,$client);probeCheck($engine->executeBan($s)&&count($client->bans)===1,'Actual engine gate failed fake ban');
 $low=probeDecision('198.18.71.3',['/owa/','/Telerik.Web.UI.WebResource.axd','/login.do'],89);probeCheck(!DecisionEligibility::applications($low)['eligible'],'Low confidence counted');
 $old=probeDecision('198.18.71.4',['/owa/','/Telerik.Web.UI.WebResource.axd','/login.do'],99,3600);probeCheck(!DecisionEligibility::applications($old)['eligible'],'Expired proof counted');
 $other=probeDecision('198.18.71.5',['/owa/']);probeCheck(!DecisionEligibility::applications($other)['eligible'],'Another IP inherited apps');
 $origin=probeDecision('198.18.71.2',['/owa/'],99,20,'/var/log/apache2/access_license_gateway.log');probeCheck(!DecisionEligibility::applications($origin)['eligible'],'Another source inherited apps');
 $monitor=$s;$monitor['classification']='monitor';probeCheck(!DecisionEligibility::applications($monitor)['eligible'],'Monitor became ban');
 $uncited=probeDecision('198.18.71.8',['/owa/','/Telerik.Web.UI.WebResource.axd','/login.do'],99,20,'/var/log/apache2/access_whmcs.log',1);probeCheck(!DecisionEligibility::applications($uncited)['eligible'],'Uncited physical events granted authority');
 $extended=probeDecision('198.18.71.9',['/sugar_version.json','/login.do','/showLogin.cc','/solr/']);
 probeCheck(DecisionEligibility::evaluate($extended)['eligible']&&DecisionEligibility::applications($extended)['applications']===3,'Real-case extended diversity not actionable');
 $extendedClient=new Fail2BanClient;probeCheck((new AutoBanEngine(null,$extendedClient))->executeBan($extended)&&isset($extendedClient->bans[$extended['ip']]),'Extended validated gate did not ban');
 $twoExtended=probeDecision('198.18.71.10',['/sugar_version.json','/login.do','/showLogin.cc']);
 Database::setConfig('ai_mode','auto');probeCheck(!DecisionEligibility::evaluate($twoExtended)['eligible'],'Two extended apps bypassed gate');Database::setConfig('ai_mode','threshold');
 $uncitedExtended=probeDecision('198.18.71.11',['/sugar_version.json','/login.do','/solr/'],99,20,'/var/log/apache2/access_whmcs.log',1);
 probeCheck(!DecisionEligibility::applications($uncitedExtended)['eligible'],'Uncited extended applications counted');
 $dup=probeLine('198.18.71.9','/solr/');probeCheck(ProbeApplications::stats([['line'=>$dup],['line'=>$dup],['line'=>$dup]],'198.18.71.9')['events']===1,'Duplicated citations counted');
 Database::setConfig('ai_application_probe_groups',"exchange\nservlet");probeCheck(!DecisionEligibility::applications($s)['eligible'],'Deselected application counted');Database::setConfig('ai_application_probe_groups',implode("\n",ProbeApplications::GROUPS));
 Database::setConfig('ai_mode','auto');Database::setConfig('ai_application_probe_enabled','0');probeCheck(!DecisionEligibility::evaluate($s)['eligible'],'Disabled application gate fell back to auto');Database::setConfig('ai_application_probe_enabled','1');Database::setConfig('ai_mode','threshold');
 // Collector fixture is private; no production log is modified or replayed.
 $tmp=tempnam('/tmp','amsfb_apps_');$lines=[probeLine('198.18.71.6','/owa/'),probeLine('198.18.71.6','/Telerik.Web.UI.WebResource.axd'),probeLine('198.18.71.6','/login.do')];file_put_contents($tmp,implode("\n",$lines)."\n");
 $stat=stat($tmp);Database::setConfig('adaptive_cursor.'.md5($tmp),json_encode(['file'=>$stat['dev'].':'.$stat['ino'],'generation'=>'fixture','offset'=>0,'anchor'=>'','draining'=>false]));
 $r=BehaviorStore::collect($tmp);$rows=C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$tmp)->get()->map(fn($r)=>(array)$r)->all();
 probeCheck($r['events']===3&&count($rows)===1,'Collector split application targets');
 $group=AnalysisWork::consolidateRows($rows,[],time(),time()-3600)[0];probeCheck(count($group['_work_events']??[])===3,'Full physical proofs lost');
 $foreign=$rows[0];$foreign['id']=hash('sha256','foreign');$foreign['source_log']='/var/log/apache2/access_license_gateway.log';probeCheck(count(AnalysisWork::consolidateRows([$rows[0]],[$foreign])[0]['_work_refs'])===1,'Sources were merged');
 $corrupt=$rows[0];$samples=json_decode($corrupt['samples'],true);$samples[0]['time']-=60;$corrupt['samples']=json_encode($samples);probeCheck(empty(AnalysisWork::consolidateRows([$corrupt])[0]['_work_events']),'Stored timestamp overrode raw proof');
 $older=$rows[0];$older['id']=hash('sha256','previous-bucket');$older['bucket']=date('Y-m-d H:i:s',time()-620);$olderSamples=json_decode($older['samples'],true);
 foreach($olderSamples as &$sample){$sample['id']=hash('sha256',$sample['id'].'older');$sample['time']-=610;$target=\AMS\Fail2Ban\RequestEvidence::target($sample['line']);$sample['line']=probeLine($sample['ip'],$target,$sample['time']);}unset($sample);
 $older['samples']=json_encode($olderSamples);$older['behavior_variants']=json_encode(array_map(fn($x)=>ProbeApplications::signature($x['line'],$x['ip']),$olderSamples));
 $merged=AnalysisWork::consolidateRows([$rows[0]],[$older],time(),time()-3600)[0];probeCheck(count($merged['_work_refs'])===2&&count($merged['_work_events'])===6,'Complete recent buckets not consolidated');
 $another=$older;$another['id']=hash('sha256','third-bucket');$more=json_decode($another['samples'],true);foreach($more as &$event)$event['id']=hash('sha256',$event['id'].'third');unset($event);$another['samples']=json_encode($more);
 probeCheck(count(AnalysisWork::consolidateRows([$rows[0]],[$older,$another],time(),time()-3600)[0]['_work_refs'])===2,'Event cap acknowledged omitted bucket');
 // Full automatic worker with provider/native/bans mocked, real SQL rolled back.
 C::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>C::raw('revision')]);C::table(AnalysisWork::BATCH_TABLE)->update(['status'=>'complete']);
 $row=$rows[0];$row['id']=hash('sha256','worker'.random_bytes(8));$row['source_log']='/var/log/apache2/access_whmcs.log';$row['analyzed_revision']=0;C::table('mod_amssoft_fail2ban_rollups')->insert($row);
 Database::setConfig('ai_cycle_max_calls','1');Database::setConfig('ai_cycle_seconds','90');
 $ai=new ApplicationWorkerAI('openai','fixture');$workerClient=new Fail2BanClient;$worker=new AutoBanEngine($ai,$workerClient);$worker->runAnalysis();
 probeCheck($ai->calls===1,'Grouped task not admitted');probeCheck(($ai->context['198.18.71.6']['application_probes']['applications']??0)===3,'Worker context missed app diversity');
 probeCheck(isset($workerClient->bans['198.18.71.6']),'Full worker did not enforce validated application criterion');
 $extendedRow=$row;$extendedRow['id']=hash('sha256','extended-worker'.random_bytes(8));$extendedRow['ip']='198.18.71.12';$extendedRow['analyzed_revision']=0;
 $extendedSamples=[];foreach(['/sugar_version.json','/login.do','/solr/'] as $i=>$path){$line=probeLine($extendedRow['ip'],$path,time()-10+$i);$extendedSamples[]=['id'=>hash('sha256',$line),'ip'=>$extendedRow['ip'],'line'=>$line,'time'=>BehaviorStore::eventTime($line),'pattern'=>$extendedRow['pattern']];}
 $extendedRow['samples']=json_encode($extendedSamples);$extendedRow['behavior_variants']=json_encode(array_map(fn($x)=>ProbeApplications::signature($x['line'],$x['ip']),$extendedSamples));C::table('mod_amssoft_fail2ban_rollups')->insert($extendedRow);
 $extendedAI=new ApplicationWorkerAI('openai','fixture');$extendedWorkerClient=new Fail2BanClient;(new AutoBanEngine($extendedAI,$extendedWorkerClient))->runAnalysis();
 probeCheck($extendedAI->calls===1&&($extendedAI->context[$extendedRow['ip']]['application_probes']['applications']??0)===3,'Extended full worker context missing');
 probeCheck(isset($extendedWorkerClient->bans[$extendedRow['ip']]),'Extended full worker failed automatic ban');
 $row['id']=hash('sha256','monitor-worker'.random_bytes(8));$row['analyzed_revision']=0;$row['ip']='198.18.71.7';$samples=json_decode($row['samples'],true);
 foreach($samples as &$event){$event['id']=hash('sha256',$event['id'].'monitor');$event['ip']=$row['ip'];$event['line']=str_replace('198.18.71.6','198.18.71.7',$event['line']);}unset($event);
 $row['samples']=json_encode($samples);$row['behavior_variants']=json_encode(array_map(fn($x)=>ProbeApplications::signature($x['line'],$x['ip']),$samples));C::table('mod_amssoft_fail2ban_rollups')->insert($row);
 $monitorAI=new ApplicationWorkerAI('openai','fixture');$monitorAI->action='monitor';$monitorClient=new Fail2BanClient;(new AutoBanEngine($monitorAI,$monitorClient))->runAnalysis();
 probeCheck($monitorAI->calls===1&&$monitorClient->bans===[],'Model monitor converted to automatic ban');
 // Full worker: recent physical observations survive a prior monitor cycle without historical ack.
 Database::setConfig('schema_version','31');Database::setConfig('ai_application_probe_history_enabled','1');
 $makeWindow=function($windowIp)use($extendedRow){$created=[];$lines=[];
  foreach(['/login.do','/solr/','/sugar_version.json'] as $i=>$path){$t=time()-[1740,1020,20][$i];$line=probeLine($windowIp,$path,$t);
   $event=['id'=>hash('sha256',$line),'ip'=>$windowIp,'line'=>$line,'time'=>$t,'pattern'=>$extendedRow['pattern']];
   $r=$extendedRow;$r['id']=hash('sha256',$windowIp.$path.random_bytes(8));$r['ip']=$windowIp;$r['events']=1;$r['revision']=1;$r['analyzed_revision']=$i<2?1:0;
   $r['processing_state']=$i<2?'processed':'pending';$r['bucket']=date('Y-m-d H:i:s',(int)(floor($t/600)*600));$r['last_event_at']=date('Y-m-d H:i:s',$t);
   $r['samples']=json_encode([$event]);$r['behavior_complete']=1;$r['behavior_variants']=json_encode([ProbeApplications::signature($line,$windowIp)]);C::table('mod_amssoft_fail2ban_rollups')->insert($r);$created[]=$r;if($i<2)$lines[]=$line;
  }
  Database::saveSuggestion(['ip'=>$windowIp,'source_log'=>$extendedRow['source_log'],'action'=>'monitor','classification'=>'monitor','severity'=>'low','confidence'=>99,'threat'=>'prior monitor fixture','filter_name'=>'window-fixture','evidence'=>$lines,'_pattern'=>$extendedRow['pattern'],'_analysis_key'=>hash('sha256',random_bytes(8))]);
  return $created;
 };
 $windowRows=$makeWindow('198.18.71.14');$windowAI=new ApplicationWorkerAI('openai','fixture');$windowClient=new Fail2BanClient;(new AutoBanEngine($windowAI,$windowClient))->runAnalysis();
 probeCheck($windowAI->calls===1&&($windowAI->context['198.18.71.14']['application_probes']['applications']??0)===3,'Prior monitor cycle lost physical app evidence');
 probeCheck(($windowAI->context['198.18.71.14']['individual_events']??0)===3&&($windowAI->context['198.18.71.14']['recent_observation_rows']??0)===2,'Window context counts contradict complete proof');
 probeCheck(isset($windowClient->bans['198.18.71.14']),'Full worker did not ban validated slow scan');
 foreach(array_slice($windowRows,0,2) as $priorRow){$live=C::table('mod_amssoft_fail2ban_rollups')->where('id',$priorRow['id'])->first();probeCheck((int)$live->revision===1&&(int)$live->analyzed_revision===1&&$live->processing_state==='processed','Historical row reopened or acknowledged again');}
 $ids=[];foreach($windowRows as $r)$ids[]=json_decode($r['samples'],true)[0]['id'];
 probeCheck(C::table('mod_amssoft_fail2ban_detections')->where('ip','198.18.71.14')->whereIn('event_id',$ids)->count()===3,'Slow scan manufactured physical IDs');
 $makeWindow('198.18.71.15');$windowMonitorAI=new ApplicationWorkerAI('openai','fixture');$windowMonitorAI->action='monitor';$windowMonitorClient=new Fail2BanClient;(new AutoBanEngine($windowMonitorAI,$windowMonitorClient))->runAnalysis();
 probeCheck($windowMonitorAI->calls===1&&($windowMonitorAI->context['198.18.71.15']['application_probes']['applications']??0)===3&&$windowMonitorClient->bans===[],'Expanded monitor was converted to ban');
 $windowProtected=$makeWindow('198.18.71.16');\AMS\Fail2Ban\Privileged::$protected=['198.18.71.16'];\AMS\Fail2Ban\BlockedTasks::refresh(true);
 $windowProtectedAI=new ApplicationWorkerAI('openai','fixture');(new AutoBanEngine($windowProtectedAI,new Fail2BanClient))->runAnalysis();probeCheck($windowProtectedAI->calls===0,'Protected slow scan sent to API');
 C::table('mod_amssoft_fail2ban_rollups')->where('ip','198.18.71.16')->update(['analyzed_revision'=>C::raw('revision')]);\AMS\Fail2Ban\Privileged::$protected=[];Database::setConfig('schema_version','28');
 // Already protected extended subjects must not reach the provider, even with new represented probes.
 $protectedRow=$extendedRow;$protectedRow['id']=hash('sha256','protected-extended-worker'.random_bytes(8));$protectedRow['analyzed_revision']=0;C::table('mod_amssoft_fail2ban_rollups')->insert($protectedRow);
 \AMS\Fail2Ban\Privileged::$protected=[$protectedRow['ip']];\AMS\Fail2Ban\BlockedTasks::refresh(true);
 $protectedAI=new ApplicationWorkerAI('openai','fixture');$protectedClient=new Fail2BanClient;(new AutoBanEngine($protectedAI,$protectedClient))->runAnalysis();
 probeCheck($protectedAI->calls===0&&$protectedClient->bans===[],'Protected extended subject spent API or renewed ban');
 \AMS\Fail2Ban\Privileged::$protected=[];\AMS\Fail2Ban\Privileged::$available=false;\AMS\Fail2Ban\BlockedTasks::refresh(true);
 $unknownAI=new ApplicationWorkerAI('openai','fixture');(new AutoBanEngine($unknownAI,new Fail2BanClient))->runAnalysis();
 probeCheck($unknownAI->calls===0,'Unknown coverage reached provider');\AMS\Fail2Ban\Privileged::$available=true;
 Database::setConfig('ai_whitelist_ips',$extended['ip']);$whitelistClient=new Fail2BanClient;
 probeCheck(!(new AutoBanEngine(null,$whitelistClient))->executeBan($extended)&&$whitelistClient->bans===[],'Whitelist extended subject was banned');Database::setConfig('ai_whitelist_ips','');
 Database::setConfig('schema_version','27');Database::setConfig('schema27_complete','1');Database::setConfig('schema28_complete','0');Database::setConfig('native_probe_groups','env');Database::setConfig('ai_cycle_max_calls','4');
 foreach(ProbeApplications::KEYS as $k)Database::setConfig($k,'');
 $db->enableQueryLog();\AMS\Fail2Ban\Migrations::run();
 probeCheck(Database::getConfig('schema_version')===(string)\AMS\Fail2Ban\Migrations::VERSION&&Database::getConfig('ai_application_probe_min_confidence')==='90','Additive migration did not seed settings');
 probeCheck(Database::getConfig('native_probe_groups')==="env\nquery_traversal"&&Database::getConfig('ai_cycle_max_calls')==='4','Migration changed policy or failed native opt-in');
 Database::setConfig('native_probe_groups','env');\AMS\Fail2Ban\Migrations::run();probeCheck(Database::getConfig('native_probe_groups')==='env','Migration re-enabled deselected group');
 foreach($db->getQueryLog() as $q)if(preg_match('/^\s*(create|alter|drop|truncate)/i',$q['query']))throw new RuntimeException('Unexpected migration DDL');
 Database::setConfig('schema_version','29');Database::setConfig('schema29_complete','1');Database::setConfig('schema30_complete','0');Database::setConfig('ai_application_probe_groups',implode("\n",ProbeApplications::LEGACY_GROUPS));Database::setConfig('ai_application_probe_enabled','0');
 \AMS\Fail2Ban\Migrations::run();probeCheck(Database::getConfig('ai_application_probe_groups')===implode("\n",ProbeApplications::GROUPS),'Old default not promoted');probeCheck(Database::getConfig('ai_application_probe_enabled')==='0','Migration reenabled disabled protection');
 Database::setConfig('ai_application_probe_groups',"solr\nservlet");\AMS\Fail2Ban\Migrations::run();probeCheck(Database::getConfig('ai_application_probe_groups')==="solr\nservlet",'Migration reenabled deselected groups');
 Database::setConfig('schema_version','29');Database::setConfig('schema30_complete','0');Database::setConfig('ai_application_probe_groups',"exchange\nservlet");\AMS\Fail2Ban\Migrations::run();probeCheck(Database::getConfig('ai_application_probe_groups')==="exchange\nservlet",'Custom selection overwritten by promotion');
} finally {if($tmp&&is_file($tmp))unlink($tmp);$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} application probe checks; collector/consolidation/engine/worker, SQL rolled back, fake API/native/bans\n";
}
