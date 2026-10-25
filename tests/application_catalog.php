<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=['schema_version'=>'37'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}}
require dirname(__DIR__).'/lib/Router.php';
date_default_timezone_set('America/Sao_Paulo');
$checks=0;function catalogCheck($ok,$why){global $checks;if(!$ok)throw new \RuntimeException($why);$checks++;}
$hashes=[];$legacyCount=count(ProbeApplications::V1_GROUPS);$started=microtime(true);
for($bits=1;$bits<(1<<count(ProbeApplications::GROUPS));$bits++){
 $groups=[];foreach(ProbeApplications::GROUPS as $i=>$g)if($bits&(1<<$i))$groups[]=$g;
 $pattern=ProbeApplications::pattern($groups);
 catalogCheck(strlen($pattern)===64&&ctype_xdigit($pattern)&&!isset($hashes[$pattern]),'Invalid/colliding identity');
 $hashes[$pattern]=true;
 catalogCheck(ProbeApplications::catalogPattern($pattern),'Subset not recognized');
 if($bits<(1<<$legacyCount)){
  sort($groups,SORT_STRING);
  catalogCheck($pattern===hash('sha256','application-probe-v1|'.implode('|',$groups)),'Historical identifier changed');
 }
}
catalogCheck(microtime(true)-$started<10,'Catalogue lookup grew exponentially');
foreach(['',str_repeat('f',64),'a5500000'.str_repeat('0',56),substr(ProbeApplications::pattern(ProbeApplications::GROUPS),0,63).'z'] as $bad)
 catalogCheck(!ProbeApplications::catalogPattern($bad),'Malformed identity recognized');
$pattern=ProbeApplications::pattern(ProbeApplications::GROUPS);
catalogCheck(ProbeApplications::pattern(array_reverse(ProbeApplications::GROUPS))===$pattern,'Selection order matters');
$now=time();$ip='198.51.100.77';
function catalogLine($path,$ip='198.51.100.77',$age=0){return $ip.' - - ['.date('d/M/Y:H:i:s O',time()-$age).'] "GET '.$path.' HTTP/1.1" 403 10 "-" "fixture"';}
$rows=[];$i=0;
foreach(['ivanti_probe'=>'ivanti','globalprotect_probe'=>'globalprotect','rdweb_probe'=>'rdweb','exchange_auth_probe'=>'exchange'] as $group=>$app)
 foreach(NativeProbes::APPLICATION_TRAPS[$group] as $path){
  $line=catalogLine($path.'?probe=1');
  catalogCheck(ProbeApplications::application($line)===$app,'Native/app catalogue mismatch');
  catalogCheck(ProbeApplications::application($line,[])===null,'Unselected app recognized');
  $event=['id'=>hash('sha256',$line),'ip'=>$ip,'time'=>$now,'line'=>$line,'pattern'=>$pattern];
  $rows[]=['id'=>hash('sha256','catalog-row-'.($i++)),'revision'=>1,'analyzed_revision'=>0,'ip'=>$ip,
   'source_log'=>'/var/log/apache2/access_whmcs.log','pattern'=>$pattern,'bucket'=>date('Y-m-d H:i:s',$now),
   'samples'=>json_encode([$event]),'events'=>1,'processing_state'=>'pending'];
 }
foreach(['/','/remote/login','/Remote','/admin','/web/login','/api/v1/version','/wsman','/owa/not-the-target','/RDWeb/child','/RDWeb.bak'] as $path)
 catalogCheck(ProbeApplications::application(catalogLine($path))===null,'Generic/unknown target included');
catalogCheck(ProbeApplications::application(catalogLine('/index.php?next=/RDWeb'))===null,'Query impersonates target');
$result=AnalysisWork::consolidateRows([$rows[0]],array_slice($rows,1),$now,$now-1800)[0];
catalogCheck(count($result['_work_events'])===8&&count($result['_work_refs'])===8,'Known paths not consolidated or event cap lost');
catalogCheck(count($rows)===10,'Expected ten exact targets');
$events=array_merge(...array_map(fn($row)=>json_decode($row['samples'],true),$rows));
catalogCheck(ProbeApplications::stats($events,$ip)['applications']===4,'Different products collapsed into one application');
catalogCheck(ProbeApplications::stats($events,'198.51.100.78')['events']===0,'Cross-IP evidence accepted');
foreach(['ip'=>'198.51.100.78','source_log'=>'/var/log/apache2/error.log','blocked_confirmed_at'=>date('c'),'processing_state'=>'review','pattern'=>hash('sha256','other')] as $field=>$value){
 $bad=$rows[1];$bad[$field]=$value;
 $isolated=AnalysisWork::consolidateRows([$rows[0]],[$bad],$now,$now-1800)[0];
 catalogCheck(count($isolated['_work_refs'])===1,'Invalid candidate merged: '.$field);
}
Database::$cfg['ai_application_probe_groups']=implode("\n",ProbeApplications::V1_GROUPS);
catalogCheck(!ProbeApplications::grouped($pattern),'Custom selection overwritten');
Database::$cfg['ai_application_probe_enabled']='0';
catalogCheck(!ProbeApplications::grouped(ProbeApplications::pattern(ProbeApplications::V1_GROUPS)),'Disabled grouping enabled');
echo "PASS: {$checks} application catalogue compatibility/recognition/consolidation checks; pure, no SQL/provider/native\n";
