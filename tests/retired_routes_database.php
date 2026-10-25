<?php
namespace AMS\Fail2Ban {
class Privileged {public static function run($a){if($a[0]==='protection-snapshot')return ['success'=>true,'stable'=>true,'errors'=>[],'observed_at'=>time(),'requirements'=>['http'=>[80,443]],'entries'=>[]];throw new \RuntimeException('Unexpected native operation: '.$a[0]);}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{Database,RetiredRoutes,BehaviorStore,AnalysisWork,AIAnalyzer,AutoBanEngine,Fail2BanClient,Safety};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();date_default_timezone_set('America/Sao_Paulo');$db=C::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');$db->beginTransaction();$n=0;
function rdbCheck($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
function rdbRow($id,$target='/retired-page',$ip='198.18.85.1',$status=404){$t=time()-5;$line=$ip.' - - ['.date('d/M/Y:H:i:s O',$t).'] "GET '.$target.' HTTP/1.1" '.$status.' 10 "-" "fixture"';$pattern=BehaviorStore::pattern($line);
 return ['id'=>hash('sha256','retired-'.bin2hex(random_bytes(8)).$id),'ip'=>$ip,'source_log'=>RetiredRoutes::SOURCES[1],'pattern'=>$pattern,'bucket'=>date('Y-m-d H:i:s',(int)(floor($t/600)*600)),
 'revision'=>1,'analyzed_revision'=>0,'processing_state'=>'pending','last_event_at'=>date('Y-m-d H:i:s',$t),'events'=>1,'attempts'=>0,'samples'=>json_encode([['id'=>hash('sha256',$line.$id),'ip'=>$ip,'line'=>$line,'time'=>$t,'pattern'=>$pattern]])];}
class RetiredWorkerAI extends AIAnalyzer {public int $calls=0;public array $ips=[];public function analyzeSubjects(array $lines,array $context):array{$this->requestStarting();$this->calls++;$out=[];foreach($context as $ip=>$ctx){$this->ips[]=$ip;$out[]=['ip'=>$ip,'action'=>'monitor','confidence'=>99,'severity'=>'low','threat'=>'Fixture','evidence'=>Safety::evidence($lines,$ip),'filter_name'=>'','failregex'=>''];}return $out;}}
try{
 foreach(['schema_version'=>'31','ai_retired_local_enabled'=>'1','ai_retired_paths'=>'/retired-page','ai_retired_http403_enabled'=>'0','ai_retired_denial_correlation_enabled'=>'0','ai_mode'=>'suggestion','ai_auto_enabled'=>'1','ai_auto_create_filter'=>'0','ai_history_validation_per_cycle'=>'0','ai_rule_requests'=>'{}','ai_review_auto_recovery_enabled'=>'0','ai_queue_urgent_enabled'=>'0','ai_cycle_max_calls'=>'3','ai_queue_consolidation'=>'1'] as $k=>$v)Database::setConfig($k,$v);
 C::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>C::raw('revision')]);C::table(AnalysisWork::BATCH_TABLE)->where('status','pending')->update(['status'=>'complete']);
 $r=rdbRow('exact');C::table('mod_amssoft_fail2ban_rollups')->insert($r);rdbCheck(RetiredRoutes::finish($r),'Exact pending row not finalized');$live=(array)C::table('mod_amssoft_fail2ban_rollups')->where('id',$r['id'])->first();
 rdbCheck($live['analyzed_revision']==1&&$live['processing_state']==='observed_local','Local state absent');rdbCheck($live['samples']===$r['samples'],'Evidence changed');rdbCheck(C::table('mod_amssoft_fail2ban_ai_suggestions')->where('task_id',$r['id'])->count()===0,'Local work invented AI suggestion');
 $race=rdbRow('race');C::table('mod_amssoft_fail2ban_rollups')->insert($race);C::table('mod_amssoft_fail2ban_rollups')->where('id',$race['id'])->update(['revision'=>2]);rdbCheck(!RetiredRoutes::finish($race),'Newer revision acknowledged');rdbCheck(C::table('mod_amssoft_fail2ban_rollups')->where('id',$race['id'])->value('analyzed_revision')==0,'CAS lost');C::table('mod_amssoft_fail2ban_rollups')->where('id',$race['id'])->update(['analyzed_revision'=>2]);
 $reject=rdbRow('rejected');C::table('mod_amssoft_fail2ban_rollups')->insert($reject);$key=hash('sha256',$reject['id']."\0".$reject['revision']."\0");Database::saveSuggestion(['ip'=>$reject['ip'],'source_log'=>$reject['source_log'],'_task_id'=>$reject['id'],'_analysis_key'=>$key,'_pattern'=>$reject['pattern'],'action'=>'monitor','confidence'=>99,'status'=>'rejected']);
 rdbCheck(!RetiredRoutes::finish($reject),'Rejected decision bypassed');rdbCheck(C::table('mod_amssoft_fail2ban_rollups')->where('id',$reject['id'])->value('analyzed_revision')==0,'Rejected task acknowledged');
 rdbCheck(!RetiredRoutes::recordable($reject,json_decode($reject['samples'],true),$reject['source_log'],RetiredRoutes::paths()),'Collector bypassed rejected revision');
 C::table('mod_amssoft_fail2ban_rollups')->where('id',$reject['id'])->update(['processing_state'=>'review']);
 $plain=rdbRow('worker',status:421);C::table('mod_amssoft_fail2ban_rollups')->insert($plain);$ai=new RetiredWorkerAI('openai','fixture');(new AutoBanEngine($ai,new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client')))->runAnalysis();
 rdbCheck($ai->calls===0,'Plain retired route reached provider');rdbCheck(C::table('mod_amssoft_fail2ban_rollups')->where('id',$plain['id'])->value('processing_state')==='observed_local','Worker did not finalize local work');
 $cycles=json_decode(Database::getConfig('ai_cycle_metrics','[]'),true);$last=end($cycles);rdbCheck(($last['local_observed']??0)===1&&$last['reason']==='local_work_completed','Local-only work mislabeled idle');
 $limits=['calls'=>3,'seconds'=>180,'retry_percent'=>30];$coverage=['coverage_version'=>4,'active_jails'=>1,'missing_jail_tickets'=>0,'missing_f2b_rules'=>0,'orphan_firewall_ips'=>0,'duplicate_prefix_jails'=>0,'jails_without_actions'=>[],'jails_unverified'=>[]];
 rdbCheck(\AMS\Fail2Ban\CycleObserver::metricsValid($last,$limits,AIAnalyzer::RECOVERY_GENERATION),'Observer refused measured local-only cycle');
 rdbCheck(\AMS\Fail2Ban\CycleAcceptance::valid($last,json_decode(Database::getConfig('ai_cycle_state'),true),$coverage,$last['finished_at'],0,0,'',$limits),'Runtime acceptance refused measured local-only cycle');
 $query=rdbRow('query','/retired-page?x=1','198.18.85.2');$other=rdbRow('other','/different','198.18.85.3');C::table('mod_amssoft_fail2ban_rollups')->insert($query);C::table('mod_amssoft_fail2ban_rollups')->insert($other);
 $ai2=new RetiredWorkerAI('openai','fixture');(new AutoBanEngine($ai2,new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client')))->runAnalysis();rdbCheck($ai2->calls>0&&in_array($query['ip'],$ai2->ips,true)&&in_array($other['ip'],$ai2->ips,true),'Query/different route hidden from normal analysis');
 Database::setConfig('ai_retired_http403_enabled','1');
 $forbidden=rdbRow('403-local',ip:'198.18.85.4',status:403);C::table('mod_amssoft_fail2ban_rollups')->insert($forbidden);
 $ai3=new RetiredWorkerAI('openai','fixture');(new AutoBanEngine($ai3,new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client')))->runAnalysis();
 rdbCheck($ai3->calls===0,'Opt-in exact retired 403 reached provider');
 rdbCheck(C::table('mod_amssoft_fail2ban_rollups')->where('id',$forbidden['id'])->value('processing_state')==='observed_local','403 worker did not finalize locally');
 rdbCheck(C::table('mod_amssoft_fail2ban_ai_suggestions')->where('task_id',$forbidden['id'])->count()===0,'403 local work invented paid suggestion');
 Database::setConfig('ai_retired_http403_enabled','0');
 $off=rdbRow('403-disabled',ip:'198.18.85.5',status:403);C::table('mod_amssoft_fail2ban_rollups')->insert($off);
 $ai4=new RetiredWorkerAI('openai','fixture');(new AutoBanEngine($ai4,new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client')))->runAnalysis();
 rdbCheck($ai4->calls>0&&in_array($off['ip'],$ai4->ips,true),'Disabling 403 did not restore normal analysis');
 $h=RetiredRoutes::health();rdbCheck($h['tasks']>=2&&$h['events']>=2,'Local counters absent');rdbCheck(Database::getConfig('ai_last_error','')==='','Worker recorded error');
}finally{$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$n} retired-route database/worker checks; SQL rolled back, fake provider/native, no real bans\n";
}
