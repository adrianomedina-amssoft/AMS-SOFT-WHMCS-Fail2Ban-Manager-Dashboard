<?php
namespace AMS\Fail2Ban {
class Privileged {
    public static int $reads=0;
    public static function run($args){
        if($args[0]!=='protection-snapshot')throw new \RuntimeException('Simulation attempted mutation/provider operation');
        self::$reads++;return ['success'=>true,'stable'=>true,'errors'=>[],'observed_at'=>time(),
            'requirements'=>['http'=>[80,443]],'entries'=>[]];
    }
}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,Policy,ProbeSimulation,ProbeApplications,BehaviorStore,AIDashboard,Migrations,Privileged,DecisionMemory};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
$db=C::connection();if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');
$db->beginTransaction();$checks=0;$now=time();
function simCheck($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
function simRow($ip,$paths,$source='/var/log/apache2/access_whmcs.log',$age=10){
    global $now;$events=[];foreach($paths as $i=>$path){$t=$now-$age+$i;
        $line=$ip.' - - ['.date('d/M/Y:H:i:s O',$t).'] "GET '.$path.' HTTP/1.1" 404 10 "-" "fixture"';
        $events[]=['id'=>hash('sha256',$line),'ip'=>$ip,'time'=>$t,'line'=>$line];}
    return ['ip'=>$ip,'source_log'=>$source,'samples'=>json_encode($events),'events'=>count($events)];
}
function simSnapshot(){return ['success'=>true,'stable'=>true,'errors'=>[],'observed_at'=>time(),'ttl'=>300,
    'requirements'=>['http'=>[80,443]],'entries'=>[]];}
try{
    // This fixture exercises simulation migration, not the exact legacy prompt migration.
    Database::setConfig('ai_prompt','Custom simulation fixture {logs}');
    $original=Policy::values();$activeCatalog=ProbeApplications::CATALOG;
    Migrations::run();simCheck(Database::getConfig('schema_version')===(string)Migrations::VERSION,'Current schema missing');
    simCheck(Database::getConfig('ai_prompt')==='Custom simulation fixture {logs}','Unknown custom prompt overwritten');
    foreach($original as $key=>$v)if(!in_array($key,array_merge(ProbeSimulation::KEYS,['ai_application_probe_groups']),true))simCheck(Policy::values()[$key]===$v,'Migration altered policy '.$key);
    Database::setConfig('ai_probe_simulation_enabled','0');Migrations::run();simCheck(Database::getConfig('ai_probe_simulation_enabled')==='0','Migration reactivated simulation');
    foreach(ProbeSimulation::KEYS as $k)Database::setConfig($k,(string)Policy::fields()[$k][2]);
    $p=ProbeSimulation::policy();$now=time();$snapshot=simSnapshot();$snapshot['observed_at']=$now;
    $fingerprint=DecisionMemory::policyFingerprint();Database::setConfig('ai_probe_simulation_min_events','4');
    simCheck(DecisionMemory::policyFingerprint()===$fingerprint,'Simulation invalidated paid memory');Database::setConfig('ai_probe_simulation_min_events','3');
    $row=simRow('198.18.72.1',['/login.do','/solr/','/sugar_version.json']);
    $r=ProbeSimulation::analyze([$row],$snapshot,$p,[],$now);
    simCheck($r['criteria_met']===1&&$r['results'][0]['applications']===3,'Expanded independent apps missing');
    simCheck($r['bans']===0&&$r['provider_calls']===0,'Simulation claims execution');
    simCheck(ProbeApplications::CATALOG===$activeCatalog,'Active catalogue altered');
    foreach(['/','/retired-page','/clientarea.php','/index.jsp','/console','/identity','/favicon.ico',
        '/index.php?file=/solr/','/solr/not-a-catalog-target','/wp-content/style.css'] as $path){
        $line=json_decode(simRow('198.18.72.1',[$path])['samples'],true)[0]['line'];
        simCheck(ProbeSimulation::application($line,ProbeSimulation::GROUPS)===null,'Normal target entered app catalogue '.$path);
    }
    $without=$p;$without['ai_probe_simulation_groups']="wordpress\nservlet";
    simCheck(ProbeSimulation::analyze([$row],$snapshot,$without,[],$now)['criteria_met']===0,'Deselected group counted');
    $foreign=simRow('198.18.72.2',['/solr/']);$own=simRow('198.18.72.1',['/login.do','/sugar_version.json']);
    simCheck(ProbeSimulation::analyze([$own,$foreign],$snapshot,$p,[],$now)['criteria_met']===0,'Another IP inherited evidence');
    $origin=simRow('198.18.72.1',['/solr/'],'/var/log/apache2/access_license_gateway.log');
    simCheck(ProbeSimulation::analyze([$own,$origin],$snapshot,$p,[],$now)['criteria_met']===0,'Origins merged');
    $dupe=simRow('198.18.72.1',['/login.do']);$raw=json_decode($dupe['samples'],true);$dupe['samples']=json_encode([$raw[0],$raw[0],$raw[0]]);$dupe['events']=3;
    simCheck(ProbeSimulation::analyze([$dupe,$dupe],$snapshot,$p,[],$now)['results'][0]['events']===1,'Duplicate physical evidence counted');
    $servlet=simRow('198.18.72.1',['/login.do','/showLogin.cc','/solr/']);
    simCheck(ProbeSimulation::analyze([$servlet],$snapshot,$p,[],$now)['results'][0]['applications']===2,'Same app paths counted as apps');
    $bad=$row;$e=json_decode($bad['samples'],true);foreach($e as &$event)$event['time']--;unset($event);$bad['samples']=json_encode($e);
    simCheck(ProbeSimulation::analyze([$bad],$snapshot,$p,[],$now)['subjects']===0,'Stored time overrode raw event');
    $bad=$row;$bad['ip']='198.18.72.2';simCheck(ProbeSimulation::analyze([$bad],$snapshot,$p,[],$now)['subjects']===0,'Wrong peer accepted');
    simCheck(ProbeSimulation::analyze([simRow('198.18.72.1',['/login.do'],age:7200)],$snapshot,$p,[],$now)['subjects']===0,'Old proof accepted');
    simCheck(ProbeSimulation::analyze([simRow('198.18.72.1',['/login.do'],age:-30)],$snapshot,$p,[],$now)['subjects']===0,'Future proof accepted');
    simCheck(ProbeSimulation::analyze([$row],$snapshot,$p,['198.18.72.1'],$now)['excluded_whitelist']===1,'Whitelist counted');
    $protected=$snapshot;$protected['entries']=[['ip'=>'198.18.72.1','effective'=>true,'protocol'=>'tcp','ports'=>[80,443],
        'jail'=>'fixture','ticket'=>'fixture','expires_at'=>$now+600]];
    $r=ProbeSimulation::analyze([$row],$protected,$p,[],$now);simCheck($r['subjects']===0&&$r['excluded_protected']===1,'Protected peer was analysed as candidate');
    foreach(['success','stable'] as $key){$unknown=$snapshot;$unknown[$key]=false;simCheck(ProbeSimulation::analyze([$row],$unknown,$p,[],$now)['status']==='coverage_unavailable','Unknown coverage accepted');}
    $unknown=$snapshot;$unknown['observed_at']=$now-301;simCheck(ProbeSimulation::analyze([$row],$unknown,$p,[],$now)['criteria_met']===0,'Expired coverage accepted');
    $unknown=$snapshot;$unknown['requirements']=[];simCheck(ProbeSimulation::analyze([$row],$unknown,$p,[],$now)['excluded_unknown']===1,'Unknown service accepted');
    $many=array_fill(0,501,$row);simCheck(ProbeSimulation::analyze($many,$snapshot,$p,[],$now)['partial'],'Row cap not disclosed');
    $partial=$row;$partial['events']=99;simCheck(ProbeSimulation::analyze([$partial],$snapshot,$p,[],$now)['omitted_events']===96,'Unrepresented events counted');
    simCheck(!str_contains(json_encode(ProbeSimulation::analyze([$row],$snapshot,$p,[],$now)),'fixture"'),'Raw event retained in report');
    $low=$p;$low['ai_analysis_recent_minutes']='5';simCheck(ProbeSimulation::analyze([simRow('198.18.72.1',['/login.do'],age:400)],$snapshot,$low,[],$now)['subjects']===0,'Recent gate widened');
    // Read model does not turn nine old decisions for one IP into nine fresh attackers.
    $projection=['groups'=>['checking'=>range(1,9)],'states'=>[]];$decisions=[];
    for($i=1;$i<=9;$i++){$projection['states'][$i]=['eligibility'=>['reason'=>'pending_new_analysis','latest'=>$now-7200]];
        $decisions[]=['id'=>$i,'ip'=>'198.18.72.1'];}
    $reasons=AIDashboard::reasonStats($projection,$decisions)['checking'][0];
    simCheck($reasons['records']===9&&$reasons['ips']===1&&$reasons['historical']===9,'Historical reason units wrong');
    // Actual bounded capture, real SQL rolled back, only protection read mocked.
    $id=hash('sha256','simulation'.random_bytes(8));$insert=$row+['id'=>$id,'pattern'=>hash('sha256',$id),
        'bucket'=>date('Y-m-d H:i:s',$now),'revision'=>1,'analyzed_revision'=>1,'last_event_at'=>date('Y-m-d H:i:s',$now),
        'processing_state'=>'processed','attempts'=>0,'validation_attempts'=>0];
    C::table('mod_amssoft_fail2ban_rollups')->insert($insert);
    $counts=[];foreach(['ai_suggestions','detections','evidence_links','analysis_batches','logs'] as $table)$counts[$table]=C::table('mod_amssoft_fail2ban_'.$table)->count();
    Database::setConfig('ai_probe_simulation_last_run','0');ProbeSimulation::capture();
    $report=ProbeSimulation::read();simCheck(Privileged::$reads===1,'Capture used operations beyond one local protection read');
    simCheck($report['status']==='measured','Report not current');
    simCheck(count(array_filter($report['report']['results'],fn($r)=>$r['ip']==='198.18.72.1'&&$r['criteria_met']))===1,'Actual capture missed represented fixture');
    foreach($counts as $table=>$count)simCheck(C::table('mod_amssoft_fail2ban_'.$table)->count()===$count,'Capture changed operational table '.$table);
    $reads=Privileged::$reads;ProbeSimulation::capture();simCheck(Privileged::$reads===$reads,'Capture interval ignored');
    Database::setConfig('ai_probe_simulation_min_events','4');simCheck(ProbeSimulation::read()['status']==='policy_changed','Old policy reported current');
    Database::setConfig('ai_probe_simulation_enabled','0');ProbeSimulation::capture();simCheck(Privileged::$reads===$reads,'Disabled simulation read native state');
    simCheck(ProbeSimulation::read()['status']==='disabled','Disabled report not labelled');
    $policy=Policy::values();foreach([['ai_probe_simulation_groups'=>'solr\n.*'],['ai_probe_simulation_min_apps'=>'4','ai_probe_simulation_min_events'=>'3']] as $input){
        $rejected=false;try{Policy::validate($input,$policy);}catch(InvalidArgumentException $e){$rejected=true;}simCheck($rejected,'Invalid simulation policy accepted');}
}finally{$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} simulation/migration/read-model checks; SQL rollback, no API or bans\n";
}
